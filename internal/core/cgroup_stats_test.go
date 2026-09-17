//go:build with_ebpf && (linux || android)

package core

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestCgroupUDPReleaseNotificationDropsSumsPerCPUCounter(t *testing.T) {
	statsMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("create per-CPU array: %v", err)
	}
	t.Cleanup(func() { _ = statsMap.Close() })

	perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
	perCPU[0] = 2
	if len(perCPU) > 1 {
		perCPU[1] = 3
	}
	index := uint32(0)
	if err = statsMap.Put(index, perCPU); err != nil {
		t.Fatal(err)
	}

	backend := &CgroupBackend{runtime: &cgroupRuntime{
		udp_release_observer: true,
		maps:                 map[string]*CiliumEBPF.Map{"cgroup_udp_release_stats": statsMap},
	}}
	drops, err := backend.UDPReleaseNotificationDrops()
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(2)
	if len(perCPU) > 1 {
		want = 5
	}
	if drops != want {
		t.Fatalf("drops = %d, want %d", drops, want)
	}
}
