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
- `runtime/tc_routing.go`
- `runtime/tc_topology.go`
- their unit and network-namespace tests

This unit owns the TC/TCX links or filters, interface locks, clsact fallback,
delivery veth, policy rules/routes, modified sysctls, retired resources,
rollback, and the `TCBackend`. Raw links, filters, qdiscs, routes, sysctl
records, BPF maps, programs, and file descriptors remain under
`internal/core`. The separate `runtime` package can borrow backend handles only
through the module's internal bridge; consumers cannot access or close them.

### Shared packet-rewrite runtime

- `runtime/shared_rewrite_dataplane.go`
- its attachment, sysctl, health, rollback, race, and network-namespace tests

This unit owns its `SharedNetworkBackend`, TC/TCX attachments, interface locks,
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

When `AttachProcessTracker` returns both a tracker and an error, cleanup could
not detach every legacy cgroup hook. The caller owns that incomplete tracker
and must retry `Close`; it must not use the tracker for process lookup.

Shared runtime callbacks execute while reconciliation owns the runtime lock.
They must remain bounded and must not call back into the same runtime. This is
an explicit adapter constraint until callback delivery is moved outside the
transactional reconciliation section.

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
collision/rollback, shared `route_localnet` restore, and fake-IP ICMP paths.
Verify consumer builds with `with_ebpf` both enabled and disabled and generated
objects for little- and big-endian targets. `boundary_test.go` must continue to
reject every sing-box or sing-tun import anywhere in the source and test tree.
