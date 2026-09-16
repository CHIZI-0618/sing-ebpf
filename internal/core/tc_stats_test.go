//go:build with_ebpf && (linux || android)

package core

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestTCStatsSumsPerCPUErrorCounters(t *testing.T) {
	statsMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: tcStatCount,
	})
	if err != nil {
		t.Skipf("cannot create a TC stats map: %v", err)
	}
	t.Cleanup(func() { _ = statsMap.Close() })
	perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
	perCPU[0] = 2
	if err := statsMap.Put(tcStatSKAssignFailure, perCPU); err != nil {
		t.Fatalf("seed TC stats map: %v", err)
	}
	if len(perCPU) > 1 {
		perCPU[1] = 3
		if err := statsMap.Put(tcStatSKAssignFailure, perCPU); err != nil {
			t.Fatalf("update TC stats map: %v", err)
		}
	}
	backend := &TCBackend{runtime: &tcRuntime{maps: map[string]*CiliumEBPF.Map{"tc_stats": statsMap}}}
	stats, err := backend.Stats()
	if err != nil {
		t.Fatalf("read TC stats: %v", err)
	}
	want := uint64(2)
	if len(perCPU) > 1 {
		want = 5
	}
	if stats.SKAssignFailures != want {
		t.Fatalf("SKAssignFailures = %d, want %d", stats.SKAssignFailures, want)
	}
	if stats.SocketLookupFailures != 0 || stats.AssignmentUpdateFailures != 0 {
		t.Fatalf("unexpected counters: %+v", stats)
	}
}
