//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestInspectMapOccupancyCountsKeys(t *testing.T) {
	requireEBPFIntegration(t, "count sing-ebpf map occupancy")
	for _, mapType := range []CiliumEBPF.MapType{CiliumEBPF.Hash, CiliumEBPF.LRUHash} {
		t.Run(mapType.String(), func(t *testing.T) {
			const maxEntries = 64
			const entries = 37
			m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
				Name:       "sb_occ_test",
				Type:       mapType,
				KeySize:    4,
				ValueSize:  1,
				MaxEntries: maxEntries,
			})
			if err != nil {
				t.Fatalf("create map: %v", err)
			}
			t.Cleanup(func() { _ = m.Close() })
			for key := uint32(0); key < entries; key++ {
				if err = m.Put(key, uint8(1)); err != nil {
					t.Fatalf("put %d: %v", key, err)
				}
			}
			info, err := m.Info()
			if err != nil {
				t.Fatalf("map info: %v", err)
			}
			id, ok := info.ID()
			if !ok {
				t.Skip("kernel does not report map IDs")
			}

			count, err := countMapKeys(m, info.KeySize, info.MaxEntries)
			if err != nil || count != entries {
				t.Fatalf("countMapKeys = %d, %v; want %d, nil", count, err, entries)
			}

			report := InspectMapOccupancy()
			for _, item := range report.Maps {
				if item.ID != id {
					continue
				}
				if !item.Supported || item.Error != "" || item.Entries != entries {
					t.Fatalf("occupancy = %+v, want %d entries without error", item, entries)
				}
				return
			}
			t.Fatalf("map %d missing from occupancy report: %+v", id, report)
		})
	}
}

func TestCountMapKeysEmptyMap(t *testing.T) {
	requireEBPFIntegration(t, "count an empty map")
	m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	count, err := countMapKeys(m, 4, 8)
	if err != nil || count != 0 {
		t.Fatalf("countMapKeys = %d, %v; want 0, nil", count, err)
	}
}
