//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestPolicyVectorEncodesEachDataPlane(t *testing.T) {
	vector := policyVector{
		EnableTCP:           true,
		EnableUDP:           true,
		EnableIPv4:          true,
		EnableLocalIPv6:     true,
		EnableSharedIPv6:    true,
		UIDPolicy:           true,
		UIDDefaultBypass:    true,
		LocalBypassPrivate:  true,
		SharedBypassPrivate: true,
		LocalBypassPort:     true,
		SharedBypassPort:    true,
		BypassIPv4:          true,
		BypassIPv6:          true,
		HostIPv4:            true,
		HostIPv6:            true,
		IncludeSource:       true,
		ExcludeSource:       true,
		IncludeSourceMAC:    true,
		ExcludeSourceMAC:    true,
		BypassFlowCache:     true,
		ForceInterceptIPv4:  true,
		ForceInterceptIPv6:  true,
	}

	tc := vector.tcFlags()
	for _, bit := range []uint32{
		tcFlagIPv4, tcFlagLocalIPv6, tcFlagSharedIPv6, tcFlagTCP, tcFlagUDP,
		tcFlagLocalBypassPort, tcFlagSharedBypassPort,
		1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 10, 1 << 11,
		1 << 12, 1 << 13, 1 << 14, 1 << 15, 1 << 16, 1 << 17,
	} {
		if tc&bit == 0 {
			t.Fatalf("TC vector omitted flag %#x: %#x", bit, tc)
		}
	}

	cgroup := vector.cgroupFlags()
	for _, bit := range []uint32{
		cgroupFlagTCP, cgroupFlagUDP, cgroupFlagIPv4, cgroupFlagIPv6,
		cgroupFlagUIDPolicy, cgroupFlagUIDDefaultBypass, cgroupFlagBypassIPv4,
		cgroupFlagBypassIPv6, cgroupFlagBypassPrivateAddress, cgroupFlagHostIPv4,
		cgroupFlagHostIPv6, cgroupFlagForceInterceptIPv4, cgroupFlagForceInterceptIPv6,
		cgroupFlagBypassPort, cgroupFlagUDPFlow,
	} {
		if cgroup&bit == 0 {
			t.Fatalf("cgroup vector omitted flag %#x: %#x", bit, cgroup)
		}
	}

	shared := vector.sharedFlags()
	for _, bit := range []uint32{
		sharedPacketRewriteFlagIPv4, sharedPacketRewriteFlagIPv6, sharedPacketRewriteFlagTCP,
		sharedPacketRewriteFlagUDP, sharedPacketRewriteFlagHostIPv4, sharedPacketRewriteFlagHostIPv6,
		sharedPacketRewriteFlagBypassIPv4, sharedPacketRewriteFlagBypassIPv6,
		sharedPacketRewriteFlagIncludeSource, sharedPacketRewriteFlagExcludeSource,
		sharedPacketRewriteFlagIncludeSourceMAC, sharedPacketRewriteFlagExcludeSourceMAC,
		sharedPacketRewriteFlagBypassPrivateAddress, sharedPacketRewriteFlagBypassFlowCache,
		sharedPacketRewriteFlagForceInterceptIPv4, sharedPacketRewriteFlagForceInterceptIPv6,
	} {
		if shared&bit == 0 {
			t.Fatalf("shared vector omitted flag %#x: %#x", bit, shared)
		}
	}
}
