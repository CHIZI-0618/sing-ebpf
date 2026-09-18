# sing-ebpf

`sing-ebpf` provides reusable Linux cgroup and TC eBPF mechanisms for transparent
TCP and UDP redirection. It owns kernel programs, generated objects, maps,
capability selection, attachment lifecycles, policy routing, and rollback. An
application remains responsible for configuration, listeners, routing policy,
and connection or session handling.

The project originated in an experimental eBPF inbound implementation for
sing-box and is now independently maintained. It is not affiliated with or
endorsed by SagerNet or the sing-box project. Application concepts such as DNS
FakeIP remain consumer-owned: the library receives only opaque force-intercept
prefixes and never reads or maintains an application's address mappings.

The API is currently experimental. Architecture, dependency policy, and
lifecycle invariants are documented in [ARCHITECTURE.md](ARCHITECTURE.md).
Build, generation, testing, debugging, and contribution procedures are in
[DEVELOPING.md](DEVELOPING.md).

## Package boundary

The dependency direction is enforced:

```text
consumer  --->  sing-ebpf/runtime  --->  sing-ebpf
semantics      network resources      BPF core and objects
               and reconciliation
```

The root package owns the BPF C sources, generated little- and big-endian
objects, Go/C ABI, maps, programs, capability selection, generic policy
compilation, redirect routes, cgroup attachment, self-bypass, and socket process
tracking. The `runtime` package owns TC/TCX attachment, clsact fallback,
delivery links, policy routes and rules, modified sysctls, shared packet rewrite,
topology reconciliation, and rollback.

A consumer owns configuration and validation, route-rule translation,
listeners, UDP NAT and session state, process metadata, router integration,
logs, counters, and user-facing diagnostics. It must not reach into generated
objects or duplicate their ABI. `boundary_test.go` recursively prevents this
module from importing the original sing-box or sing-tun application packages.

The public runtime surface is deliberately small:

- `runtime.NewTCRuntime` transfers a prepared `singebpf.TCBackend` into a
  complete TC network-resource owner;
- `runtime.NewUnstartedTCRuntime` transfers a backend into the same cleanup
  owner when application setup fails before network startup;
- `runtime.NewSharedPacketRewriteRuntime` creates a lazy shared runtime whose
  backend factory and application notifications are explicit callbacks;
- both runtimes expose reconciliation, health, lifecycle, backend access for
  flow and policy operations, and value-only diagnostics.

`SharedPacketRewriteBackend` is owned exclusively by the shared runtime. Consumers may
borrow it for flow lookup and policy updates, but must not close or retain a
second ownership handle. Failed attachment, `route_localnet`, or interface-lock
cleanup remains recorded and is retried before programs and maps are released.

A non-nil runtime returned together with a TC startup error represents failed
rollback state and must be retained until `Close` succeeds. A shared runtime
waiting for its first interface is open, not closed, even before its backend
factory has been called.

Raw map, program, and FD access is confined to `internal/core`. The sibling
`runtime` package borrows those handles through an internal bridge while
constructing attachments; external consumers receive only lifecycle façades,
value-level flow and policy operations, and diagnostics. A non-nil
`ProcessTracker` returned with an attach error owns incomplete rollback state
and must be retained until `Close` succeeds.

## Packet paths

The library has four concrete backend choices: local `tc` or `cgroup`, and
shared `socket_assign` or `packet_rewrite`. A consumer may enable either path
independently. Exported capability probes can load and close selected generated
objects without attaching them, but attachment and network-state validation
still require a real runtime startup.

Local traffic is selected at TC egress on the current default interface.
Forwarded packets are excluded through `ingress_ifindex`; consumer-owned sockets
are identified by their kernel socket cookie. An exclusive process cgroup can
populate and release the cookie map in kernel hooks. When the cgroup is shared
or cannot be attached, a consumer can register dialer and transparent-reply
socket cookies once at creation time.
Selected packets are addressed to the delivery peer, cross the veth, and are assigned at
its ingress hook. L3-only links receive an Ethernet header before this redirect.

Shared `socket_assign` traffic is selected and assigned at TC ingress on each
configured downstream interface. Shared `packet_rewrite` traffic is selected
and rewritten at ingress, then restored at egress. Local and shared roles can
be enabled independently, including with local cgroup plus shared
`packet_rewrite`.

Local egress and shared `socket_assign` ingress each have Ethernet and raw-IP
program variants; the selected variant follows the link encapsulation reported
by netlink. Shared `packet_rewrite` intentionally accepts Ethernet framing
only because it edits L2 packets in place.
`classifier/delivery_ingress` always parses Ethernet from the internal veth.
Local and delivery use the local IPv6 flag; shared uses the shared IPv6 flag.
Both flags are static for the lifetime of the inbound.

Fragmented IPv4 datagrams and non-atomic IPv6 fragments bypass before policy
selection. IPv6 atomic fragments continue through extension-header parsing.

### Optional local cgroup path

The cgroup backend attaches connect and UDP sendmsg/recvmsg programs to the
selected cgroup v2 directory. A selected destination is replaced with a token
address from a private redirect prefix and the original destination is stored
by token. TCP consumes that entry after accept. UDP retains bounded state for
the session and uses the token as the listener reply source so recvmsg can
restore the original peer.

Userspace rejects redirect address and route conflicts before attachment and
owns only the local routes it created. The TCP token map is an LRU map so
abandoned connect attempts cannot permanently exhaust it. UDP uses
socket-release cleanup when supported and bounded LRU recovery otherwise.

The interception cgroup is independent of an optional exclusive process cgroup
used for self-bypass. A broad interception cgroup still excludes consumer-owned
sockets through the shared cookie map. Userspace socket controls remain the
fallback when process cgroup hooks cannot maintain that map.

## Socket assignment

TCP listeners use a `SOCKMAP` on kernels that support the preferred listener
fallback. Established TCP lookup uses the original tuple before falling back to the
listener. If the SOCKMAP cannot be created or the modern program is rejected by the
kernel verifier, the backend loads a legacy TCP section that does not reference the map
and performs direct `bpf_skc_lookup_tcp` lookup. UDP lookup substitutes only the
internal listener port. `tc_assignment` records the original tuple, ingress
interface, shared source MAC, packet path, and (for local process matching) the
socket cookie used to recover the process owner. The separate
`tc_self_sockets` map contains only cookies of consumer-owned sockets and is
consulted by local egress before any packet interception.
The optional cgroup socket-address tracker records cookie, PID, and UID in a
bounded LRU map. Userspace then reads only `/proc/<pid>/exe` instead of scanning
all process file descriptors. If the tracker cannot be attached, normal route
process search remains the fallback. A cgroup `sock_release` hook removes owner
records immediately when supported; otherwise the bounded LRU map remains the
cleanup fallback.
Raw-IP shared links mark the source MAC as unavailable rather than publishing a
synthetic address. Source MAC policy therefore requires Ethernet framing.

UDP replies use transparent sockets bound to the original response source. The
inbound reuses one socket per original response source and closes the pool when
the inbound stops.

## Policy routing

Socket assignment preserves the original destination tuple, so selected packets
must also be routed into the local stack. Shared ingress and delivery ingress set
a dynamically allocated packet-mark bit while preserving all other mark bits. Userspace
installs matching IPv4 and IPv6 rules for a dedicated route table containing
local routes for the two halves of each address family. Two `/1` routes are used
instead of one `/0` route because Android kernels can reject a default route of
type `local`.

Policy-routing setup holds a process-external lock, chooses unused mark/table/
priority identifiers, and rejects unrelated routes or rules that already reference
the selected table. Stale matching state from
an interrupted instance is replaced during startup. Rules and routes are added
before the control map is enabled and removed only after interception is
disabled and interface filters are detached.

## Policy order

The programs first apply path-specific address-family, protocol, fragment,
service-traffic, and safety gates. Application-supplied force-intercept prefixes
force interception before other policy. DNS `off` bypasses and DNS `hijack`
intercepts before UID or shared source
policy. DNS `respect_policy` applies UID/source policy first, then intercepts
before host, private-address, and destination-CIDR bypass. Other traffic applies
the same source policy followed by those destination bypasses.

Local egress checks the socket-cookie self-bypass map. Shared source CIDR and
MAC include/exclude policies are evaluated only on the shared path.

## Object layout

| Group | Map types | Purpose |
| --- | --- | --- |
| control | `ARRAY` | Enable state, path flags, listener port, and delivery interface identity. |
| sockets and assignments | `SOCKMAP` (optional), `LRU_HASH` | Preferred TCP listener fallback, original-flow metadata, and local self-bypass cookies. Legacy TCP lookup does not use SOCKMAP. |
| prefix policy | `LPM_TRIE` | UID ranges, source CIDRs, and destination bypass CIDRs. |
| exact policy | `HASH` | Host addresses and shared source MAC policy. |
| packet rewrite scratch | `PERCPU_ARRAY` | Per-CPU scratch and counters used only by shared `packet_rewrite`. |

### LPM trie kernel safety

The LPM maps are created for a uniform object layout, but they are updated only
when the corresponding policy has entries. Linux 6.6.0 through 6.6.46 has an
upstream LPM key-layout defect that can trigger an out-of-bounds report, or a
kernel fault on affected UBSAN/fortify builds, during an update. The upstream
fix (`bpf_lpm_trie_key_u8`) is present in 6.6.47 and may be backported by a
vendor.

Because a generic map-type probe cannot safely detect this defect, policy setup
uses a conservative release check for that range and accepts it only when the
fixed BTF type is positively visible. If the fix cannot be confirmed, setup
fails before issuing an LPM update. Other kernel capabilities continue to use
runtime map, program, and helper probes; this version check is limited to the
LPM update safety exception.

The object is generated for little-endian and big-endian BPF without BTF or
CO-RE sections. Source and object hashes are recorded in
`internal/bpfgen/manifest.txt`.

## Lifecycle

Importing the module or constructing an unstarted runtime does not install a
process-wide socket wrapper. Shared-only consumers do not need local socket
hooks.

For a TC runtime, startup loads maps and programs, registers consumer-provided
TCP listeners, allocates non-conflicting policy-routing identifiers, creates the
delivery link when local mode is configured, attaches available interfaces,
loads host and bypass policy, and enables the control map last. Local mode may
start without a default interface; its egress attachment is added after a
network update.

When local process matching is required, a consumer may attach the cgroup
socket-address tracker. It is an optional optimization and must be closed with
the owning application lifecycle; shared-only mode does not require self-bypass
or process-tracking state.

Default-interface and raw network-update callbacks feed one bounded event queue.
The worker refreshes the interface inventory, follows the current default
interface for local interception, and compares every attachment by name,
ifindex, framing, role, and installed filter identity. It also validates policy
routing and the delivery link after network changes. Missing rules, routes,
filters, delivery link state, and delivery sysctls are restored without periodic
polling.

Configured shared interfaces that are absent at startup are attached when they
appear; deleted or recreated interfaces are detached or replaced. A configured
shared interface is temporarily excluded while it is the current default
upstream and becomes eligible again when it returns to a downstream role. This
allows one Android interface name to alternate between Wi-Fi uplink and hotspot
operation. Topology reconciliation purges userspace UDP state, disables the
control map, replaces attachments and host policy, and then enables the backend.
A failed update attempts to restore the previous state before re-enabling. When
the default interface disappears, the last local attachment is retained until a
new interface is available.

Runtime shutdown disables interception, detaches filters or BPF links, removes
policy routing, restores delivery sysctls, removes the veth, and closes programs
and maps. The consumer must stop callbacks and close its listeners and sessions
before releasing the runtime. Startup failures use the same reverse-order
cleanup path.

For local cgroup mode, the consumer selects redirect prefixes and supplies
listeners; the backend prepares routes and maps, loads the enabled program set,
and attaches it last. Shared `packet_rewrite` uses separate listeners and token
routes. Shared `socket_assign` uses TC listeners and policy routing without a
delivery veth. Any combination of local and shared choices is valid. Shutdown
detaches each selected backend and removes only routes owned by that instance. A
disabled path does not load its object or create network state.

## Building, generation, and tests

This section is the short path for consumers. Developers changing the BPF C,
Go/C ABI, loaders, capability selection, or lifecycle code must also follow the
full [development guide](DEVELOPING.md).

The Go packages require Linux or Android and the `with_ebpf` build tag. Normal
builds use the checked-in generated objects and do not require cgo, bpftool,
kernel BTF, or an Android NDK.

Generated objects use Android NDK r29 Clang 21:

```bash
make generate
make check
```

Run correctness and ABI tests with:

```bash
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
```

Kernel program and attachment tests require Linux root privileges and explicit
opt-in:

```bash
sudo env SING_EBPF_INTEGRATION=1 \
  go test -tags 'with_ebpf ebpf_integration' ./...
```
