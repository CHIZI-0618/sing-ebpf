# eBPF decision boundary

`sing-ebpf` is a data-plane library. Its policy boundary is the final action
performed by the kernel program:

- `DecisionPass`: leave the packet or socket operation alone;
- `DecisionIntercept`: redirect or assign it to the eBPF listener.

The library must not know why an action was selected. Concepts such as DNS
mode, FakeIP, route rule-sets, private-address policy, package names, or
sing-box configuration compatibility belong to sing-box. sing-box compiles
those inputs into action rules before updating the eBPF data plane.

The generic rule primitives in `decision.go` are deliberately limited to the
match key and the final action. A rule does not carry an `include`, `exclude`,
`bypass`, or `hijack` meaning. Those are sing-box policy concepts.

## Runtime status

All four data paths now have action-level update entry points:

1. cgroup socket hooks: `CgroupBackend.UpdateDestinationDecisions`;
2. local TC: `TCBackend.UpdateLocalDestinationDecisions`;
3. shared TC socket assignment: `TCBackend.UpdateSharedDestinationDecisions`;
4. shared packet rewrite: `SharedPacketRewriteBackend.UpdateDestinationDecisions`.

The process tracker likewise accepts `UIDDecision` values and a final default
action. Dynamic rule-set changes are compiled by sing-box into canonical
destination `pass` decisions before they cross this boundary. The library
keeps transactional map replacement, default action handling, self-bypass,
flow cleanup, and capability-selected fallback behavior.

The selector-based API has been removed. The root package intentionally exposes
only final-action policy construction and action-level runtime updates. This
prevents downstream callers from accidentally treating the library as a
second sing-box configuration compiler. Static action policy is constructed
when a backend is prepared; a configuration reload should replace that
backend/inbound rather than mutate selector state in place.

The mutable destination-action entry points are deliberately narrower: they
are for sing-box's dynamic rule-set pass updates only. They replace the
destination pass map transactionally and do not reinterpret DNS, FakeIP,
private-address, UID, package, MAC, or port configuration. Process tracking
also receives only final UID actions and is enabled by sing-box according to
its `router.NeedFindProcess()` decision.

## Ownership matrix

| Concern | sing-box | sing-ebpf |
| --- | --- | --- |
| JSON/config validation | yes | no |
| DNS/FakeIP/rule-set meaning | yes | no |
| UID/package/MAC/CIDR/port priority | yes | no |
| Compile a final pass/intercept decision | yes | no |
| BPF map key ABI and updates | no | yes |
| cgroup/TC attachment and fallback | no | yes |
| socket assignment, packet rewrite and cleanup | no | yes |
| one-shot runtime/occupancy diagnostics | no | yes |

Data-plane parameters that are required to execute an action remain library
inputs: listener descriptors, redirect prefixes, interfaces, cgroup path,
map capacities, and network-generation state. They are not policy decisions.

The migration is intentionally ordered by blast radius: cgroup first, then
local TC, shared TC socket assignment, and finally shared packet rewrite. A
path is not considered migrated merely because its Go type contains
`Decision`; its native program must consume action-valued maps and its tests
must prove pass/intercept behavior for overlapping rules and update rollback.
