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
The final-action policy boundary and consumer integration contract are in
[DECISION_MODEL.md](DECISION_MODEL.md).
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

On-demand map occupancy diagnostics include library-owned `MapCategory` metadata.
`runtime` maps describe live state and `configured_policy` maps describe
capacity derived from the compiled policy; consumers should use this category
instead of maintaining a map-name classification list.

## Packet paths

### Independent mechanism selection

`cgroup` and `packet_rewrite` are compatibility-oriented.
`socket_assign` is experimental and requires more kernel capabilities; it
preserves TCP **and** UDP tuples in a private namespace. Migrate the old local
name `tc` to `socket_assign`; it is not an alias.

| Local | Shared | Mechanisms |
| --- | --- | --- |
| cgroup | packet_rewrite | Socket-address + Ethernet packet rewrite; no assignment namespace |
| cgroup | socket_assign | cgroup hooks + independent shared assignment namespace |
| socket_assign | packet_rewrite | Local assignment namespace + independent shared rewrite |
| socket_assign | socket_assign | One assignment engine/namespace, independent scope policies |

Either scope can run alone. TCP/UDP selection applies to enabled scopes;
IPv6 is independent per scope. Disabled paths cannot enable another path's
IPv6 listener or change its policy. Optional cgroup self-bypass/process
tracking is not a mandatory dependency of socket assignment. Missing
capabilities fail startup explicitly; no mechanism silently changes.

The library has three mechanisms and four selectable scope paths: local `socket_assign` or `cgroup`, and
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
For isolated socket assignment, selected packets cross a veth into a private
network namespace and are assigned at its ingress hook. L3-only links receive
an Ethernet header before this redirect. TCP and UDP keep their original IP
addresses and ports; this is not packet/token rewriting.
Both veth ends get explicit locally administered MAC addresses at creation. The
host end is visible to udevd, and systemd's default link policy would otherwise
replace its kernel-generated address after the private namespace's static
neighbor entry was set to it. When udevd manages the caller's network namespace,
the runtime also waits, bounded by 3 s, until udevd has finished processing the
host end before configuring it, so udev's link policy and sysctls cannot undo
that configuration moments later. The runtime remembers the private end's address
programmed as the redirected frames' destination; the health check reports a
changed address and the repair reprograms the backend in place.

Shared `socket_assign` traffic is selected at TC ingress on each configured
downstream interface and uses the same isolated TCP/UDP delivery. Shared `packet_rewrite` traffic is selected
and rewritten at ingress, then restored at egress. Local and shared roles can
be enabled independently, including with local cgroup plus shared
`packet_rewrite`.

Local egress and shared `socket_assign` ingress each have Ethernet and raw-IP
program variants; the selected variant follows the link encapsulation reported
by netlink. Shared `packet_rewrite` intentionally accepts Ethernet framing
only because it edits L2 packets in place.
Delivery always parses Ethernet from the internal veth. Local and shared
selection use their own IPv6 flags; isolated delivery accepts either enabled family.
Both flags are static for the lifetime of the inbound.

Consumers create `runtime.NewTCNamespace` before their transparent listeners,
use its `Path()` for TCP, UDP and transparent UDP reply sockets, and pass the namespace to `runtime.NewTCRuntime`.
Outbound dialers stay in the host namespace. Close the runtime and sockets
before closing the caller-owned namespace. No named namespace, mount point,
holder process, host NAT rule, or host-wide sysctl change is needed.
Bind isolated UDP listeners to `127.0.0.1` / `::1`; TCP listeners remain wildcard.
The UDP lookup uses loopback without changing the received packet's tuple,
avoiding conflicts when a remote UDP endpoint has the listener's own port.
A namespace is mandatory for socket assignment; the host-namespace alternative
and `TCConfig.Isolated` switch have been removed.

The host veth ingress returns replies directly to the recorded original
interface (ingress for local clients; egress for shared clients), outside host
NAT. Assignment metadata and return routing have separate lifetimes:
`sb_tc_assign` is consumable metadata, while `sb_tc_return` is a bounded HASH.
Only TCP connection setup (SYN) records assignment metadata: the consumer takes
it once at accept, and established segments refresh only the return route, so
they neither pay the assignment lookup nor recreate a consumed entry.
Consumers retain return handles for live TCP/UDP sessions and reply aliases;
the maintenance worker cleans only unreferenced idle records. Full capacity
rejects new flows instead of evicting active return paths. Counters distinguish
publication failure, competing publishers and missing return records.

The private reply route uses the smallest selected interface MTU. Its IP stack
segments TCP and, when enabled by the consumer, fragments UDP before direct
return. A bounded `sb_tc_rfrag` LRU cache carries the first fragment's return
path to subsequent IPv4/IPv6 fragments for at most two seconds; it cannot evict
live flow routes. The worker reclaims expired fragment records. A cache miss
drops the fragment and increments the return-lookup failure counter.

Fragmented IPv4 datagrams and non-atomic IPv6 fragments bypass before policy
selection. IPv6 atomic fragments continue through extension-header parsing.

### Compatibility-oriented local cgroup path

The cgroup backend attaches connect and UDP sendmsg/recvmsg programs to the
selected cgroup v2 directory. A selected destination is replaced with a token
address from a private redirect prefix and the original destination is stored
by token. TCP consumes that entry after accept. UDP retains bounded state for
the session and uses the token as the listener reply source so recvmsg can
restore the original peer.

Userspace rejects redirect address and route conflicts before attachment and
owns only the local routes it created. A socket bound to an interface
(`SO_BINDTODEVICE`, `IP_UNICAST_IF` or `IPV6_UNICAST_IF`, as systemd-resolved
binds its DNS sockets) routes with that interface as the required output
device, which skips the prefix's loopback route and would send the redirected
connection out of the interface. `LocalRouteSet.ReconcileInterfaceRoutes`
therefore also installs each prefix as a local route on every interface that is
up and has an address of the prefix's family, with that address as the
preferred source so replies return on the bound interface; an IPv4 prefix is
also installed on the loopback interface ahead of them, so unbound sockets keep
`127.0.0.1`. These routes carry `rtm_protocol` 83, and the consumer reconciles
them again after every interface or address change. The TCP token map is an LRU map so
abandoned connect attempts cannot permanently exhaust it. UDP uses
socket-release cleanup when the optional multi-program probe succeeds;
otherwise it uses bounded LRU recovery. The probe never performs an
unflagged legacy attach, so it cannot replace an existing Android/netd
socket-release owner merely to test the optional capability.

The kernel puts a cgroup hook in single-program mode when a program is attached
without `BPF_F_ALLOW_MULTI`, and then rejects every multi-program attachment on
that hook, `BPF_LINK_CREATE` included. The backend displaces exactly one kind
of such owner: a pass-through, such as the placeholder (`return BPF_ALLOW`)
that Android 15+ netd attaches to the connect, sendmsg and recvmsg hooks of
the cgroup v2 root. The owner must be the single program of a hook in
single-program (or override) mode, and its translated instructions must reduce
to `r0 = 1; exit`. Program names, BTF and pin paths differ between AOSP,
vendor and custom-ROM netd builds, so they are not part of the decision. Only
when the kernel withholds the instructions is the owner accepted on identity,
and then only if it is netd's pinned program. The owner is replaced
atomically with an attach that uses the hook's own flags, so the hook keeps
the single-program mode a restarting netd depends on. This is reported as
attach mode `legacy_netd_replace`. The owner is held open and attached again
when the backend detaches, so the hook ends up as netd left it. netd's
socket-release program does traffic-accounting cleanup and is never displaced;
UDP cleanup then uses the LRU fallback on those devices. Every other owner is
kept: attachment fails with `ErrCgroupHookOccupied`, whose message names the
programs on the hook and why the owner was kept. While the backend holds such
a hook, it is the hook's only program, so a second backend or the process
tracker cannot attach there. A foreign owner attached without any flag to the
cgroup v2 root also blocks that hook in every descendant cgroup, so selecting
another cgroup path does not help; the TC data plane is the alternative. At
startup the backend reclaims stale interception programs (all of them when no
other backend is alive on the cgroup, otherwise only those of its own instance
slot) and any `sb_proc_*` program left as the sole single-program owner of a
hook by an earlier build. On a device with netd, a stale program that is the
sole single-program owner of a takeable hook is swapped for netd's pinned
program, or for an equivalent `sb_hook_allow` pass-through when that pin is
not at hand, instead of being detached: an emptied hook would let the next
attach put it in multi-program mode, and a restarting netd aborts on that.

`NewSelfBypass` creates no kernel object. Consumers build it while
constructing their configuration, which also happens in unprivileged
configuration checks (for example a desktop client's check worker); the
socket-cookie map is created on first use instead: data-plane preparation,
cgroup attachment, or the first socket registration. Data planes obtain it
through `PreparedMap`, so a creation failure stops startup instead of leaving
the data plane with a private map that never sees registered sockets.

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
`tc_self_sockets` map (shared as `sb_self_sockets`) contains consumer self-bypass
flags and, when UID policy tracking is enabled, application socket policy flags.
Local egress checks the self-bypass bit before interception and uses the policy
bits when evaluating UID decisions. CIDR bypass rules do not populate this map.
The optional cgroup socket-address tracker records cookie, PID, and UID in a
bounded LRU map. Userspace then reads only `/proc/<pid>/exe` instead of scanning
all process file descriptors. The tracker always attaches to the cgroup v2
root, which is also the default interception cgroup, so it uses only
multi-program attachment and never leaves a root hook in single-program mode.
If the tracker cannot be attached, normal route process search remains the
fallback. The tracker's root-cgroup `sock_release`
hook removes both owner records and any UID policy metadata for the released
cookie. The consumer's narrower self-bypass release hook cannot clean up sockets
created by applications outside its cgroup. When the tracker release hook is
unavailable, both maps retain bounded LRU fallback, so occupancy can remain high
after sockets close. Its capability probe is multi-only and does not displace an
existing cgroup owner.
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

Policy-routing setup holds a process-external instance slot, chooses unused
mark/table/priority identifiers while it holds a short allocation mutex shared
with every other runtime, and rejects unrelated routes or rules that already
reference the selected table. Each slot prefers identifiers of its own, and a
runtime replaces stale state found under exactly its slot's identifiers, which
an interrupted holder of the slot left behind; slot 0's are those of
single-instance builds. Rules and routes are added
before the control map is enabled and removed only after interception is
disabled and interface filters are detached.

## Policy order

The programs first apply path-specific address-family, protocol, fragment,
service-traffic, and safety gates. Application-supplied force-intercept prefixes
force interception before other policy. Local and shared force-prefix sets
are independent and support multiple prefixes per family. ICMP echo reply
answers, per scope and family, the intercept prefixes whose decisions set
`CIDRDecision.EchoReply`, or every intercept prefix of the family when no
decision does; a VPN range intercepted beside a FakeIP range is then not
answered locally. Port actions run
before source selectors by default, or after selectors when
`PortDecision.AfterSelectors` is true; then destination bypass applies.
Port 53 has no special meaning in native code. Consumers such as sing-box
compile DNS modes into these generic port actions.

Local egress checks the socket-cookie self-bypass map. Shared source CIDR and
MAC include/exclude policies are evaluated only on the shared path. If either
include list is configured, CIDR and MAC are alternative selectors (OR); a
matching CIDR or MAC exclude always wins. Local and shared destination-bypass
CIDR maps are separate, so a consumer can update `local.bypass_rule_set` and
`shared.bypass_rule_set` independently without aliasing policy state.

## Multiple instances

Several runtimes and backends, in one process or in several, can attach to the
same interface, cgroup and network namespace: for example two inbounds that
intercept different shared clients, or a local and a shared runtime on one
interface. Each attachment holds an instance slot of its resource, up to 16 per
interface, per cgroup and per network namespace for policy routing. A slot is an
abstract unix socket the kernel releases with its owner, so holding one also
proves that state left under its names is stale. Slot 0 keeps the lock names,
filter names, handles, program names and preferred routing identifiers of
single-instance builds.

- **TC and TCX.** Each runtime's clsact filters carry its slot in their name and
  handle (`sb_tc_shared`, `sb_tc_shared.1`, ...), so no runtime touches
  another's. TCX is used at every TC priority: every sing-ebpf program on a TCX
  hook carries its runtime's priority in a bound one-entry map
  (`sb_tcx_prio`), and a runtime inserts itself before the first sing-ebpf
  program with a larger priority, retrying when the hook revision changes. On
  clsact the kernel orders filters by the same priority. Programs pass traffic
  they do not select (`TC_ACT_UNSPEC`, which TCX treats as next), so a packet
  is handled by the first runtime in hook order that selects it. The relative
  order of runtimes with equal priorities is unspecified; give them distinct
  priorities when it matters. Reading the order needs `CAP_SYS_ADMIN`; without
  it a runtime attaches through clsact instead.
- **Policy routing.** Socket assignment routes inside its private namespace.
  Every runtime owns its own mark bit, table and rule priority there,
  preferring those of its routing slot so that the next holder of the slot can
  reclaim what an interrupted runtime left behind.
- **Shared settings.** A shared packet-rewrite interface's `route_localnet` is
  reference counted with leases: a runtime that leaves while another still
  depends on the setting leaves it in place, and the last one restores the
  original value.
- **cgroup.** Backends sharing a cgroup hold a shared lock on it and run their
  programs in attach order, descendants' before ancestors'. A later backend
  never redirects a destination an earlier one already redirected: IPv4
  redirect tokens lie in `127.0.0.0/8`, and IPv6 tokens carry the marker
  `5eb6` at the start of their interface identifier, so a destination in
  `fc00::/7` with that marker is never redirected by the cgroup path. Programs
  of slot `n` > 0 carry a hexadecimal `_n` suffix (`sb_ebpf_conn4_3`). Slots
  are per network namespace, so backends sharing a cgroup are expected to share
  one; a backend that finds a lock holder of its cgroup in another namespace
  reclaims no slot's leftovers. On a kernel that rejects multi-program
  attachment the first backend attaches exclusively and the next reports
  `ErrCgroupHookOccupied`.

Each runtime or backend still needs its own listeners, listener ports and
redirect prefixes, and a consumer must keep every runtime from intercepting
another's outbound sockets: share one `SelfBypass` between the runtimes of one
process, and use UID or process-cgroup policy across processes.

Builds without multi-instance support hold slot 0 of an interface or of policy
routing exclusively and an exclusive lock on a cgroup, so they never share
kernel names with this build. They do not take part in shared-setting leases,
however: do not run one beside this build with shared `packet_rewrite` on the
same interface.

`AttachmentInfo.Slot`, `TCNetworkInfo.RoutingSlot` and
`CgroupBackend.InstanceSlot` report the slots a runtime holds.

## Object layout

| Group | Map types | Purpose |
| --- | --- | --- |
| control | `ARRAY` | Enable state, path flags, listener port, and delivery interface identity. |
| sockets and assignments | `SOCKMAP` (optional), `LRU_HASH` | Preferred TCP listener fallback, original-flow metadata, and local self-bypass cookies. Legacy TCP lookup does not use SOCKMAP. |
| local cgroup UDP state | `HASH`/`LRU_HASH`, `LRU_HASH` | Redirect/token maps use preallocated `HASH` with socket-release cleanup, or bounded `LRU_HASH` without it; peer state follows the same capability and flow state is always bounded. |
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
filters, delivery link state, delivery sysctls, and a changed delivery peer
address are restored without periodic polling.

Configured shared interfaces that are absent at startup are attached when they
appear; deleted or recreated interfaces are detached or replaced. A configured
shared interface is temporarily excluded while it is the current default
upstream and becomes eligible again when it returns to a downstream role. This
allows one Android interface name to alternate between Wi-Fi uplink and hotspot
operation. Topology reconciliation purges userspace UDP state, disables the
control map, replaces attachments and host policy, and then enables the backend.
A failed update attempts to restore the previous state before re-enabling. When
the default interface disappears, the last local attachment is retained until a
new interface is available. Retired TC and shared packet-rewrite resources are
kept in bounded cleanup queues (16 entries per queue); when cleanup failures
persist, the oldest retained reference is evicted at the bound instead of
allowing file descriptors and memory to grow without limit.

Runtime shutdown disables interception, detaches filters or BPF links, removes
policy routing, restores delivery sysctls, removes the veth, and closes programs
and maps. The consumer must stop callbacks and close its listeners and sessions
before releasing the runtime. Startup failures use the same reverse-order
cleanup path.

For local cgroup mode, the consumer selects redirect prefixes and supplies
listeners; the backend prepares routes and maps, loads the enabled program set,
and attaches it last. Shared `packet_rewrite` uses separate listeners and token
routes. Isolated shared `socket_assign` uses the same namespace listeners,
bidirectional veth and private policy routing as local socket assignment. Any combination of
local and shared choices is valid. Shutdown
detaches each selected backend and removes only routes owned by that instance. A
disabled path does not load its object or create network state.

## Platform requirements

The library has no universal minimum kernel release. The selected data plane is
accepted only after its maps, programs, helpers, verifier load, and attachment
path pass runtime probes; vendor backports and configuration differences make a
release number alone insufficient.

The compatibility CI includes a restricted stable 4.19.325 profile (cgroup and
shared `packet_rewrite` TCP/UDP), 5.4 compatibility paths and 5.10/6.6 full paths.
Cgroup UDP reply rewriting requires recvmsg hooks introduced in mainline 5.2
and backported to the pinned 4.19.325 stable kernel; older patch levels may lack
them. Socket assignment requires `bpf_sk_assign` from 5.7. Thus 4.19 is not a
full-feature minimum. These are validation targets and feature boundaries,
not a guarantee for every kernel with the same version; see [DEVELOPING.md](DEVELOPING.md).

### Standard Linux and OpenWrt

Use a Linux kernel with BPF syscall support, cgroup v2 when the local
`cgroup` path is enabled, and the TC classifier facilities required by the
selected path. Isolated local socket assignment and shared socket assignment additionally need
`CONFIG_NET_NS`, `CONFIG_VETH`, `CAP_SYS_ADMIN` for `unshare`/`setns`, and
`CAP_NET_ADMIN` for private routes, links and transparent sockets. These
facilities predate `bpf_sk_assign` and do not raise that path's upstream kernel
feature floor. Netkit, `bpf_redirect_peer`, TCX and a global BTF are not required.
Kernels without namespaces can still use cgroup/packet-rewrite paths.
`packet_rewrite` needs Ethernet
framing; `socket_assign` can also use the documented raw-IP and tunnel link
types. Run the probe and service as root; [Runtime privileges](#runtime-privileges)
lists the individual capabilities.

On OpenWrt, install kernel modules built for the exact target kernel rather than
host distribution packages. Depending on the target and data plane these are
commonly named `kmod-bpf`, `kmod-veth`, `kmod-sched-core`, and the BPF/TC
classifier module; names vary by release. Confirm that cgroup2 and
the cgroup2 hierarchy is mounted; bpffs is only needed where pinned netd or
other pin-based integration is used. The sing-ebpf binary does not require `ip`, `tc`,
`bpftool`, or libbpf executables at runtime.

### Root Android

Root is necessary but not sufficient. The root service must see a writable
cgroup v2 hierarchy, Android bpffs/netd pins when coexistence is required, and
the BPF/TC capabilities granted by the vendor SELinux policy. Android kernels
commonly restrict cgroup hooks or TCX independently; runtime fallbacks are
selected separately. A denied optional socket-release or process-tracking hook
does not by itself make the main data plane unsupported.

Isolated local socket assignment and shared socket assignment also need vendor namespace
creation/reentry permissions (including SELinux), veth, TC, routes and sysctls;
cgroup-only local interception does not need veth or TC. Shared
`packet_rewrite` requires an Ethernet-framed downstream interface, while
`socket_assign` supports the documented L3/raw-IP variants. Validate the exact
device with `sing-box tools ebpf status` and a real startup, recording the build
fingerprint, kernel configuration, SELinux denials, and selected fallback modes.

The checked-in objects are pure-Go runtime assets: users do not need an Android
NDK, clang, bpftool, or BTF/CO-RE. Maintainers regenerate them with Android NDK
r29 Clang 21 and commit both endian variants and the manifest.

## Runtime privileges

Creating the maps and programs needs `CAP_BPF` or `CAP_SYS_ADMIN` in the initial
user namespace; attachment additionally needs `CAP_NET_ADMIN`, and startup
cleanup reads attached programs by ID, which needs `CAP_SYS_ADMIN`. Run the
consumer as root. Kernels before 5.11 also charge BPF memory to the per-user
`RLIMIT_MEMLOCK` budget; the library raises it to unlimited, which needs
`CAP_SYS_RESOURCE`. cilium/ebpf reports every `EPERM` from object creation as
a possible memlock problem, so the library replaces that hint with the
diagnosed cause: missing capabilities, a non-initial user namespace, or a
memlock limit that could not be raised.

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
