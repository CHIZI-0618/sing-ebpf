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

The older selector-based API remains as a compatibility surface for existing
standalone users and low-level integration tests. New sing-box code must not
use it for configuration semantics; it is deliberately not extended with
DNS, FakeIP, rule-set, package, or other sing-box concepts. It can be removed
in a future breaking release after downstream consumers have migrated.

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
