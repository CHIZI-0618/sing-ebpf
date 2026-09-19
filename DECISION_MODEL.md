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

## Migration status

The existing selector-based API is retained temporarily while the four
runtime paths are migrated independently:

1. cgroup socket hooks;
2. local TC;
3. shared TC socket assignment;
4. shared packet rewrite.

During migration, new action-rule APIs must be added before removing the old
selector API. Each path must retain transactional map replacement, default
action handling, self-bypass, flow cleanup, and capability-selected fallback
behavior. The selector API is removed only after sing-box has moved its policy
compiler and all four paths have action-level regression coverage.

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
