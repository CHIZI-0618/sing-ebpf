//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

func validateCgroupMapCapacity(capacity CgroupMapCapacity) error {
	for name, value := range map[string]uint32{
		"tcp_redirect":  capacity.TCPRedirect,
		"udp_redirect":  capacity.UDPRedirect,
		"udp_peer":      capacity.UDPPeer,
		"udp_flow":      capacity.UDPFlow,
		"socket_bypass": capacity.SocketBypass,
	} {
		if value == 0 || value > MaxConfigurableMapCapacity {
			return E.New("invalid eBPF ", name, " map capacity: ", value)
		}
	}
	return nil
}

func (b *CgroupBackend) updateDestinationCIDRPolicy(policy dualStackCIDRPrefixes) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	if len(policy.ipv4) > maxDestinationCIDRPolicyEntries || len(policy.ipv6) > maxDestinationCIDRPolicyEntries {
		return false, E.New("eBPF cgroup bypass CIDR policy exceeds map capacity")
	}
	if err := checkLPMTriePolicyCompatibility("eBPF cgroup bypass CIDR", len(policy.ipv4)+len(policy.ipv6)); err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	previousIPv4, previousIPv6 := b.bypassIPv4CIDR, b.bypassIPv6CIDR
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_bypass_ipv4"],
		b.runtime.maps["cgroup_bypass_ipv6"],
		dualStackCIDRPrefixes{previousIPv4, previousIPv6},
		dualStackCIDRPrefixes{policy.ipv4, policy.ipv6},
		"eBPF cgroup ", "bypass CIDR",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return false, E.Errors(err, b.health.invalidate("cgroup", "bypass CIDR policy"))
		}
		return false, err
	}
	// The cgroup program consults the destination-CIDR bypass map only when
	// the corresponding BypassIPv4/BypassIPv6 control flag is set. Those flags
	// were derived once, at prepare time, from the static pass policy (the
	// initial bypass set). A later UpdateDestinationDecisions call changes the
	// map but left the flags behind, so destinations added dynamically (for
	// example a rule-set refresh) were written to the map yet never consulted.
	// Recompute the flags from the new policy and refresh the control block,
	// matching TCBackend.updateDestinationCIDRPolicy.
	previousIPv4Flag, previousIPv6Flag := b.runtime.bypass_ipv4_policy, b.runtime.bypass_ipv6_policy
	b.bypassIPv4CIDR = slices.Clone(policy.ipv4)
	b.bypassIPv6CIDR = slices.Clone(policy.ipv6)
	b.runtime.bypass_ipv4_policy = len(policy.ipv4) > 0
	b.runtime.bypass_ipv6_policy = len(policy.ipv6) > 0
	if err = b.updateCgroupControl(b.listenerPort); err != nil {
		// The map is already live while the flags that gate it are not, and
		// the program reads the flag before the map, so leaving this half
		// applied changes what the data plane matches. Put both back.
		_, restoreErr := replaceDualStackCIDRPolicy(
			b.runtime.maps["cgroup_bypass_ipv4"],
			b.runtime.maps["cgroup_bypass_ipv6"],
			dualStackCIDRPrefixes{policy.ipv4, policy.ipv6},
			dualStackCIDRPrefixes{previousIPv4, previousIPv6},
			"eBPF cgroup ", "bypass CIDR",
		)
		if restoreErr != nil {
			return false, E.Errors(err, restoreErr, b.health.invalidate("cgroup", "bypass CIDR policy"))
		}
		b.bypassIPv4CIDR, b.bypassIPv6CIDR = previousIPv4, previousIPv6
		b.runtime.bypass_ipv4_policy, b.runtime.bypass_ipv6_policy = previousIPv4Flag, previousIPv6Flag
		return false, err
	}
	return changed, nil
}

// UpdateDestinationDecisions applies final pass decisions to the local
// cgroup destination maps. The caller has already evaluated all configuration
// and rule-set semantics; this low-level backend only stores the pass action.
func (b *CgroupBackend) UpdateDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	policy, err := compileDestinationPassDecisions(decisions)
	if err != nil {
		return false, err
	}
	return b.updateDestinationCIDRPolicy(policy)
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func (b *CgroupBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostAddresses(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("eBPF cgroup host address policy exceeds map capacity")
	}
	ipv4Prefixes := make([]netip.Prefix, len(ipv4))
	for index, address := range ipv4 {
		ipv4Prefixes[index] = netip.PrefixFrom(netip.AddrFrom4(address), 32)
	}
	ipv6Prefixes := make([]netip.Prefix, len(ipv6))
	for index, address := range ipv6 {
		ipv6Prefixes[index] = netip.PrefixFrom(netip.AddrFrom16(address), 128)
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	previous := dualStackCIDRPrefixes{b.hostIPv4, b.hostIPv6}
	next := dualStackCIDRPrefixes{ipv4Prefixes, ipv6Prefixes}
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["cgroup_host_ipv4"],
		b.runtime.maps["cgroup_host_ipv6"],
		previous,
		next,
		"eBPF cgroup ", "host address",
	)
	if err != nil {
		if policyRollbackFailed(err) {
			return E.Errors(err, b.health.invalidate("cgroup", "host address policy"))
		}
		return err
	}
	b.hostIPv4 = slices.Clone(ipv4Prefixes)
	b.hostIPv6 = slices.Clone(ipv6Prefixes)
	if changed && b.listenerPort != 0 {
		if err = b.updateCgroupControl(b.listenerPort); err != nil {
			_, rollbackErr := replaceDualStackCIDRPolicy(
				b.runtime.maps["cgroup_host_ipv4"],
				b.runtime.maps["cgroup_host_ipv6"],
				next,
				previous,
				"eBPF cgroup ", "host address rollback",
			)
			b.hostIPv4 = slices.Clone(previous.ipv4)
			b.hostIPv6 = slices.Clone(previous.ipv6)
			if rollbackErr != nil {
				return E.Errors(err, rollbackErr, b.health.invalidate("cgroup", "host address control"))
			}
			return E.Cause(err, "update cgroup host address control")
		}
	}
	return nil
}

// CgroupPolicyCapacity is intentionally fixed for the optional backend. The
// local data-plane selector must not add another user-facing tuning surface.
func cgroupPolicyCapacity() CgroupMapCapacity {
	return DefaultCgroupMapCapacity()
}
