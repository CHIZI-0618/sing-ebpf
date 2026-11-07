# Architecture and maintenance contract

This document records the dependency boundary, resource ownership, ABI rules,
and release gate for the standalone `sing-ebpf` module.

## Dependency direction

The module may depend directly on upstream releases of:

- `github.com/cilium/ebpf`
- `github.com/sagernet/netlink`
- `github.com/sagernet/sing`
- `go4.org/netipx`
- `golang.org/x/net`
- `golang.org/x/sys`

It must not depend on `github.com/sagernet/sing-box`, `sing-tun`, a fork of
`sing`, or an application logging/configuration package.

Consumers depend on this module in one direction and remain responsible for
interpreting their own configuration and route rules.

## Data-plane ownership matrix

| Path | Root package owns | `runtime` owns | Consumer owns |
| --- | --- | --- | --- |
| local cgroup | object selection, token/original maps, redirect routes, cgroup links, release cleanup | none | listeners, accepted TCP metadata, UDP NAT/session state, UID/package policy |
| local socket assignment | programs/maps, scoped policy, assignment/return state, cookie self-bypass | default-interface attachment, private-netns delivery veth and routing, reconciliation | namespace lifetime, listeners/sessions, process metadata, interface events, diagnostics |
| shared socket assignment | programs/maps, assignments, return routes, source policy | downstream attachment, isolated delivery veth, private policy routing, reconciliation | namespace lifetime, listeners, shared-source metadata, TCP/UDP handling |
| shared packet rewrite | rewrite programs/maps, flow lookup/update and counters | downstream attachment, `route_localnet`, health and rollback | token listeners, userspace flow lifecycle, policy translation, warning presentation |

The consumer may combine one local and one shared choice per runtime, and may
run several runtimes on the same interfaces, cgroups and network namespace. A
path disabled by the consumer must not load its object, attach a hook, create a
route, start a worker, or change a sysctl. No library package may interpret FakeIP mappings,
route-rule objects, package names, or a consumer's API schema.

Force-intercept prefixes are deliberately generic. They allow a consumer to
give selected destinations precedence over ordinary bypass policy without the
library learning why those prefixes are special. A consumer intercepting a
FakeIP range beside another range of the same family marks with
`CIDRDecision.EchoReply` the prefixes the ICMP echo responder answers.

## Atomic ownership units

Keep the root package, `runtime/`, `native/`, `internal/bpfgen/`, the generation
Makefile, test fixtures, and the source/object manifest in one module. BPF C
sources, both endian variants of generated objects, Go ABI declarations, map
layouts, program selection, and loaders are one versioned unit and must never
be split across repositories or releases.

Each directory under `runtime/` remains part of a complete resource owner:

### TC socket-assignment runtime

- `runtime/tc_dataplane.go`
- `runtime/tc_reconcile.go`
- `runtime/tc_netlink.go`
- `runtime/tc_delivery.go`
- `runtime/tc_namespace.go` and `runtime/tc_isolated_delivery.go`
- `runtime/tc_routing.go`
- `runtime/tc_topology.go`
- their unit and network-namespace tests

This unit owns the TC/TCX links or filters, interface locks, clsact fallback,
delivery veth, policy rules/routes, modified sysctls, retired resources,
rollback, and the `TCBackend`. Raw links, filters, qdiscs, routes, sysctl
records, BPF maps, programs, and file descriptors remain under
`internal/core`. The separate `runtime` package can borrow backend handles only
through the module's internal bridge; consumers cannot access or close them.

For isolated delivery, `TCNamespace` is a separate caller-owned lifetime:
create it before TCP/UDP listeners, pass it to the runtime, then close it after
the runtime and all listener/reply sockets. It owns an anonymous namespace FD,
not a named mount or holder process. The runtime owns a cross-namespace veth;
its routes/rules and delivery sysctls are confined to that namespace. Host
interface attachment and outbound dialing remain outside it.

`native/tc_isolation.h` preserves IP/port tuples and records a separate return
route. `internal/core/tc_return.go` owns opaque generation handles and consumer
references. TCP accept may consume assignment metadata without removing its
return route. UDP sessions retain primary and reply-alias handles. The bounded
HASH rejects admission when full, and the shared maintenance entry point skips
live references while reclaiming idle orphan/closed routes. Releasing the last
reference does not immediately remove the record: FIN/ACK and in-flight replies
retain the activity grace. Failed publication, conflicting publishers and
missing replies have separate native counters.

### Shared packet-rewrite runtime

- `runtime/shared_rewrite_dataplane.go`
- its attachment, sysctl, health, rollback, race, and network-namespace tests

This unit owns its `SharedPacketRewriteBackend`, TC/TCX attachments, interface locks,
per-interface `route_localnet` changes, retired resources, and rollback. Its
only application interactions are the explicit callbacks for userspace-flow
invalidation, readiness, and warning delivery. It must not retain a consumer
adapter.

The generic TC attachment primitives and TCX capability cache are shared by
these two runtimes inside the standalone module. Do not duplicate them or move
only `tc_netlink.go` as a public helper package.

## Stable consumer surface

A consumer adapter should consume only:

- policy/config value types and compiler functions;
- cgroup, self-bypass, process-tracker, redirect-route, TC, and shared-network
  lifecycle owners;
- TC and shared runtime constructors;
- reconciliation, enable/disable, health, close, and value-only diagnostic
  snapshots;
- explicit callback values that contain no consumer application types.

Raw program/map handles and FDs are not extension points. They are valid only
while the owning backend remains open and are structurally confined to
`internal/core`; the public façade deliberately exposes no raw accessor.

The exported `runtime.TCRuntime` and
`runtime.SharedPacketRewriteRuntime` interfaces are the mechanism contracts. An
application may alias them behind adapter-side bridge files so its startup,
monitoring, diagnostics, retry scheduling, and shutdown remain independent of
implementation details.

On-demand map occupancy is also library-owned. `MapCategory` distinguishes live
runtime state from capacity derived from compiled policy; `occupancy_mode`,
`eviction_mode`, and `admission_critical` describe how a consumer should read
the result. Consumers must not recreate this metadata from kernel map names.

`runtime.TCRuntime.TCDiagnostics` is the boundary for effective TC runtime
state: attachment mechanism, listener lookup mode, delivery/routing values,
resource counts, priority, and rebuild status. It is a value-only snapshot
and never exposes kernel handles or performs periodic map scans. The consumer
may add monitor-owned health timestamps and network generations, but must not
turn the library snapshot into a packet counter or a second lifecycle owner.

Keep the following in the consumer:

- JSON options, defaulting, and validation;
- application route-rule and rule-set translation;
- Android package/user to UID conversion;
- listener construction and accepted-connection metadata;
- process lookup/cache integration;
- UDP NAT/session and transparent reply socket pools;
- router, Clash API, counters, warning rate limits, and user-facing logs.

## Lifetime invariants

Every exported resource owner must be nil-safe where documented, have an
idempotent `Close`, and retain enough state to retry cleanup after a partial
detach failure. Cleanup order is:

1. stop callbacks and reconciliation workers;
2. disable interception in the control map;
3. detach active and retired links/filters;
4. remove policy routing and restore sysctls;
5. remove delivery links;
6. close programs and maps;
7. release process-external interface/resource locks.

Startup failure uses the same owner and reverse-order cleanup. A runtime may
remove only routes, rules, qdiscs, sysctls, links, and attachments it created or
positively reclaimed as its own. It must never delete an unrelated object's
state solely because a numeric handle matches.

## Multi-instance coordination

Several runtimes and backends may share an interface, a cgroup and a network
namespace. Kernel state that has to be told apart between them is keyed by an
instance slot (`internal/core/instance_slot.go`): clsact filter names and
handles by an interface slot and a make-before-break generation, preferred
policy-routing identifiers by a routing slot, and cgroup program names by a
cgroup slot. A slot is an abstract unix socket bound for the owner's lifetime,
and it stays held while any attachment, including one that could not detach,
still has state under its names. Positively reclaiming state as one's own
therefore means holding the slot whose names it carries; a cgroup backend that
holds the cgroup lock exclusively, proving no other backend is alive, may
reclaim every slot's. Slot names are scoped to a network namespace, so a cgroup
backend that finds a lock holder of its cgroup in another namespace reclaims no
slot's programs. Slot 0 keeps the names of single-instance builds, which locked
it exclusively.

A setting that several runtimes depend on at once, a shared packet-rewrite
interface's `route_localnet`, is reference counted with enumerable leases that
carry the value to restore; only the last holder restores it. Socket assignment
changes no host-wide setting: its sysctls live in its private namespace. Short critical sections
that read and then claim shared state, such as policy-routing identifier
selection and lease bookkeeping, take an instance mutex. TCX programs carry
their runtime's priority in a bound marker map and are inserted in priority
order with a revision-checked anchor.

When `AttachProcessTracker` returns both a tracker and an error, cleanup could
not detach every legacy cgroup hook. The caller owns that incomplete tracker
and must retry `Close`; it must not use the tracker for process lookup.

Shared runtime notification callbacks are queued while reconciliation or
cleanup owns the runtime lock and delivered in the same order after the lock is
released. They may query or re-enter the runtime without deadlocking. The
`PrepareBackend` hook is a synchronous resource factory rather than a
notification; it participates in the locked reconciliation transaction, must
not call back into the runtime, and transfers a successful backend to it.

## ABI and release rules

- Regenerate little- and big-endian objects together after any BPF C or ABI
  change.
- Require the source/object manifest freshness check in CI.
- Version the Go ABI and embedded objects in the same module release.
- Keep optional kernel features on probed fallback paths; do not infer vendor
  kernel capability from the release string alone.
- Preserve verifier logs and typed capability results at the public boundary.

## Release acceptance gate

Before publishing or updating a consumer, require all of the following:

```text
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
make check
```

Also run privileged network-namespace tests for TCX and clsact fallback,
interface recreation, partial detach retry, delivery-veth repair, policy-route
collision/rollback, shared `route_localnet` restore, multi-instance attachment,
and force-intercept ICMP Echo Reply paths.
Verify consumer builds with `with_ebpf` both enabled and disabled and generated
objects for little- and big-endian targets. `boundary_test.go` must continue to
reject every sing-box or sing-tun import anywhere in the source and test tree.

## Maintenance and diagnostics

Shared rewrite and TC assignment/return jobs use one bounded scheduling model,
with independent cursors, deadlines and pressure state. Activity coalesces;
partial scans continue shortly, failures back off, and a minute watchdog
observes kernel-only allocations. Complete scans are required to clear pressure.
Each map receives at most the per-pass budget, including batch lookups.
Batch fallback resets traversal accounting; purge and orphan scans use separate
cursors.

Return-map enumeration does not hold the reference mutex. Deletion locks one
candidate and rechecks references, generation and activity. This is a userspace
recheck, not atomic compare-and-delete against a concurrent kernel writer.
Return handles pin live consumers. One-second activity hints have a minimum
two-second cleanup grace.

`RuntimeResources` snapshots resource IDs from owners.
`InspectRuntimeResources` reads only those IDs and reports shutdown races
as unavailable, not empty. Global name inspection is a standalone debugging
tool, never proof of inbound ownership. IDs are metadata, not closeable handles.
