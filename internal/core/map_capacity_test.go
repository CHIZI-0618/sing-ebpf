//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestCompactMapCapacities(t *testing.T) {
	if got := processSocketOwnerMapCapacity("android"); got != 8192 {
		t.Fatalf("Android process-owner capacity = %d, want 8192", got)
	}
	if got := processSocketOwnerMapCapacity("linux"); got != processSocketOwnerCapacity {
		t.Fatalf("Linux process-owner capacity = %d, want %d", got, processSocketOwnerCapacity)
	}
	if got := CompactCgroupMapCapacity().SocketBypass; got != 8192 {
		t.Fatalf("compact cgroup socket-bypass capacity = %d, want 8192", got)
	}
	if got := CompactSharedPacketRewriteMapCapacity().Bypass; got != 8192 {
		t.Fatalf("compact shared bypass capacity = %d, want 8192", got)
	}
	if CompactSelfBypassSocketCapacity != 8192 || CompactTCAssignmentCapacity != 8192 {
		t.Fatal("compact self-bypass and TC assignment capacities must remain aligned")
	}
}
