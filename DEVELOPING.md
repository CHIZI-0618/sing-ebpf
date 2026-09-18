# Developing sing-ebpf

This guide describes the repository workflow for changes to BPF programs,
generated objects, Go control-plane code, capability fallbacks, and network
resource lifecycles. Read [ARCHITECTURE.md](ARCHITECTURE.md) first when changing
package boundaries or ownership.

## Supported development lines

- `dev` follows the sing-box testing/development dependency line.
- `main` remains compatible with the stable/backport consumer line.

Do not update `github.com/sagernet/sing`, `netlink`, `x/sys`, `x/net`, or
`netipx` in isolation merely to obtain a newer revision. Align them with the
consumer line, review semantic changes used by this module, and verify both the
library and consumer. `github.com/cilium/ebpf` may be updated independently only
when Android/Linux support and generated-object behavior remain compatible.

The module must not use a sing-box or sing-tun fork. The dependency direction
is always consumer → sing-ebpf.

## Repository map

| Location | Responsibility |
| --- | --- |
| `native/` | BPF C programs, shared parsers/policy helpers, and C ABI declarations |
| `internal/bpfgen/` | Checked-in little-/big-endian objects, generated Go bindings, and source/object manifest |
| `internal/core/` | Raw maps/programs/FDs, loaders, capability selection, probes, and low-level lifecycle owners |
| root package | Public value types, policy compilation, backend façades, flow operations, and capability results |
| `runtime/` | TC/TCX attachment, routes/rules, veth/sysctl ownership, topology reconciliation, health, and rollback |
| `testing/checksumoffload/` | Real-NIC checksum and segmentation-offload verification tool |

Raw kernel handles must stay below `internal/core`. Adding a public accessor to
an `ebpf.Map`, `ebpf.Program`, link FD, filter handle, or netlink resource is a
boundary change, not a convenience method.

## Choose the correct layer

Before editing, classify the requirement:

- packet parsing, policy decision, rewrite/assignment, or a kernel counter:
  `native/` plus the mirrored Go ABI and generated objects;
- map/program construction, feature probing, attachment primitive, or raw
  cleanup: `internal/core`;
- topology, route/rule, qdisc/filter, veth, sysctl, retry, and transaction:
  `runtime/`;
- application configuration, DNS/FakeIP meaning, listener/session behavior,
  route rules, package names, process cache, logging, or API output: consumer.

If a generic library feature was motivated by FakeIP or another application
concept, name it by its mechanism (`force_intercept`, prefix priority, flow
metadata), not by the consumer feature.

## Ordinary Go changes

The library is build-tagged for Linux/Android eBPF consumers. Run:

```sh
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
```

Changes to public APIs also require a consumer build with and without
`with_ebpf`. A build without the tag and a process without an eBPF inbound must
not install hooks, change dial behavior, create goroutines, or touch kernel
network state.

## BPF C and generated objects

Generation is intentionally reproducible and pinned to Android NDK r29 Clang
21. Normal consumers use checked-in objects and need neither cgo nor the NDK.

Set `ANDROID_NDK_HOME` when r29 is not installed at the Makefile default, then
run:

```sh
make generate
make check
```

`make generate`:

1. clears host include-path environment variables;
2. compiles every selected object for `bpfel` and `bpfeb` with `-mcpu=v1`;
3. strips BTF and CO-RE sections;
4. regenerates Go bindings; and
5. records generator, dependency, source, and object hashes in
   `internal/bpfgen/manifest.txt`.

Commit C sources, Go ABI changes, both endian object variants, bindings, and the
manifest together. Never make CI the only place that regenerates objects, and
never hand-edit generated `.go`, `.o`, or manifest content.

### ABI checklist

For every C structure used as a map key/value or control record:

1. compare C and Go size, alignment, field offsets, signedness, byte order, and
   reserved bytes;
2. initialize every key byte, including padding;
3. add or update compile-time C assertions and Go layout tests;
4. check map type, key/value size, flags, maximum entries, and per-CPU shape for
   replacements;
5. regenerate both endiannesses and run manifest freshness checks; and
6. load every affected object variant on a real kernel.

Changing only the Go mirror while leaving an embedded object untouched can
compile successfully and still corrupt lookup semantics.

## Capability and fallback changes

Kernel release numbers are not positive capability evidence. Vendor kernels
backport and disable facilities independently. A new optional path needs:

- a probe for the exact map, program type, helper, link or attach flag used;
- representative object loading when verifier behavior matters;
- a deterministic fallback that does not reference the unavailable facility;
- runtime diagnostics for the path that actually loaded/attached; and
- tests that force the primary path to fail and prove the fallback semantics.

The Linux 6.6 LPM-trie defect is the deliberate exception: probing by updating
the map can itself fault affected kernels, so the safety deny-list and positive
BTF evidence are kept separate from ordinary capability selection.

Current important fallbacks include TCX → owned `clsact`, SOCKMAP-capable TCP →
legacy TCP lookup, cgroup socket-release notification → bounded LRU cleanup,
and cgroup multi-program → compatible legacy exclusive attachment. Do not turn
an optional fallback failure into a silent feature claim; diagnostics must name
the effective path.

## Lifecycle and concurrency review

Trace construction, successful start, partial start, reconcile, and close.
Every resource must have one owner and appear in reverse-order cleanup. Verify:

- interception is enabled only after listeners, maps, attachments, routes, and
  required sysctls are ready;
- a failed replacement preserves the last working state or reports why it was
  disabled;
- a non-nil owner returned with an error remains closeable and retained until
  cleanup succeeds;
- `Close` is idempotent and retries partial detach/restore failures;
- only positively owned qdiscs, filters, routes, rules, links, locks, and
  sysctls are removed;
- workers are cancellable and joined; timers do not create idle wakeups without
  a concrete unobservable state to check; and
- callbacks are never invoked while holding a lock they can re-enter.

Shared runtime notifications are delivered after releasing the runtime lock.
`PrepareBackend` is different: it is a synchronous factory inside the
reconciliation transaction and must not call back into the runtime.

## Test layers

### Unit, race, vet, and generation

Run the ordinary Go commands above plus `make check`. Tests should cover the
smallest value-level policy/ABI rule and injected failure before relying on a
network namespace.

### Privileged real-kernel tests

On a disposable Linux host or VM with root privileges:

```sh
sudo env \
  "PATH=$PATH" \
  SING_EBPF_INTEGRATION=1 \
  go test -v -count=1 -race \
    -tags with_ebpf,ebpf_integration \
    ./...
```

Set `SING_EBPF_REQUIRE_TCX=1` only on a host where TCX is expected and should be
a hard requirement. The normal integration suite must also exercise `clsact`
fallback instead of treating TCX as universally available.

The privileged matrix should cover all affected combinations:

- IPv4 and IPv6; TCP and UDP;
- local TC and cgroup; shared socket assignment and packet rewrite;
- Ethernet and supported raw-IP framing where applicable;
- object-load and attach fallback selection;
- interface absence, recreation, role change, and ifindex reuse;
- route/rule collision, partial startup, detach failure, and cleanup retry;
- fragmented packet pass behavior and pass/failure counters;
- UDP flow creation, reply restoration, timeout, release, queue pressure, and
  map-capacity behavior; and
- FakeIP-independent force-intercept prefixes and ICMP responder paths when
  changed.

### Real device and NIC tests

Android vendor behavior, netd coexistence, SELinux, cgroup delegation, raw-IP
rmnet framing, hotspot transitions, and power/wakeup behavior require a real
device. Packet rewrite and checksum changes additionally require the physical
NIC procedure in `testing/checksumoffload`; veth/virtio tests cannot expose
firmware offload defects.

Record the exact kernel, device, build fingerprint, configuration, selected
runtime paths, before/after diagnostics, and graceful cleanup. A probe result
alone is not an attachment or traffic test.

## Debugging evidence

For verifier failures, retain the complete verifier log and identify the exact
object/program variant. For runtime failures, collect:

- active attachment descriptions and effective mechanisms;
- first error and timestamp, recovery state, and retry deadline;
- map occupancy/capacity and relevant failure/pass counters before and after a
  controlled flow;
- routes, rules, links, qdiscs and filters owned by the test; and
- pstore/dmesg for any kernel fault.

Avoid adding packet-path logging or periodic full-map scans as diagnostics.
Prefer per-event/per-CPU counters and request-driven inspection.

## Consumer integration checklist

Before updating a consumer revision:

1. compare its `sing`, `netlink`, `x/sys`, `x/net`, and `netipx` versions with
   this branch;
2. review APIs and semantics used for socket controls, UDP OOB/batch I/O,
   process ownership, network updates, listener close/error behavior, and route
   metadata;
3. build the consumer with and without its eBPF tag;
4. run its adapter tests for configuration, listener/session ownership,
   diagnostics, and shutdown; and
5. verify the library commit is reachable before committing a consumer
   dependency update.

No textual conflict and a successful compile are not compatibility evidence.
Upstream implementations can change error, EOF, locking, caching, or lifecycle
semantics without changing a function signature.

## Documentation and release gate

Update README/architecture/development documentation when ownership, a public
API, a fallback, a runtime path, or the generated toolchain changes. Consumer
documentation owns application configuration and user-visible behavior.

Before publishing a library revision, require:

```text
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
make check
privileged real-kernel tests for affected paths
consumer builds with and without eBPF support
```

Keep implementation commits reviewable and independently revertible. A release
tag marks a tested compatibility point; it should not be created for every
commit.
