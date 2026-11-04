//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"os"
	"sort"
	"strings"

	CiliumEBPF "github.com/cilium/ebpf"
)

// MapOccupancy describes one sing-ebpf map observed by an explicit diagnostic
// request. It is intentionally not collected by any runtime worker.
type MapOccupancy struct {
	ID                CiliumEBPF.MapID `json:"id"`
	Name              string           `json:"name"`
	Category          MapCategory      `json:"category"`
	Type              string           `json:"type"`
	MaxEntries        uint32           `json:"max_entries"`
	KeySize           uint32           `json:"key_size"`
	ValueSize         uint32           `json:"value_size"`
	Flags             uint32           `json:"flags"`
	Entries           uint32           `json:"entries,omitempty"`
	Pressure          string           `json:"pressure"`
	OccupancyMode     string           `json:"occupancy_mode"`
	EvictionMode      string           `json:"eviction_mode"`
	AdmissionCritical bool             `json:"admission_critical"`
	Supported         bool             `json:"supported"`
	Error             string           `json:"error,omitempty"`
}

// MapCategory identifies the semantic role used when interpreting map
// occupancy diagnostics.
type MapCategory string

const (
	// MapCategoryRuntime identifies maps that hold live runtime state.
	MapCategoryRuntime MapCategory = "runtime"
	// MapCategoryConfiguredPolicy identifies maps whose capacity is derived
	// from the currently compiled policy.
	MapCategoryConfiguredPolicy MapCategory = "configured_policy"
)

// mapMetadata is the library-owned semantic metadata for a kernel map. The
// kernel exposes only its name and layout through map info; keeping the
// classification here prevents consumers from duplicating sing-ebpf's map
// naming scheme.
type mapMetadata struct {
	category          MapCategory
	evictionMode      string
	admissionCritical bool
}

const (
	mapEvictionNone         = "none"
	mapEvictionLRUSafeCache = "lru_safe_cache"
)

var configuredPolicyMapMetadata = map[string]mapMetadata{
	"sb_cg_force4":    {category: MapCategoryConfiguredPolicy},
	"sb_cg_force6":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_lforce4":   {category: MapCategoryConfiguredPolicy},
	"sb_tc_lforce6":   {category: MapCategoryConfiguredPolicy},
	"sb_tc_sforce4":   {category: MapCategoryConfiguredPolicy},
	"sb_tc_sforce6":   {category: MapCategoryConfiguredPolicy},
	"sb_sh_force4":    {category: MapCategoryConfiguredPolicy},
	"sb_sh_force6":    {category: MapCategoryConfiguredPolicy},
	"sb_icmp_lforce4": {category: MapCategoryConfiguredPolicy},
	"sb_icmp_lforce6": {category: MapCategoryConfiguredPolicy},
	"sb_icmp_sforce4": {category: MapCategoryConfiguredPolicy},
	"sb_icmp_sforce6": {category: MapCategoryConfiguredPolicy},
	"sb_cg_byp_port":  {category: MapCategoryConfiguredPolicy},
	"sb_cg_uid":       {category: MapCategoryConfiguredPolicy},
	"sb_proc_uid":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_uid":       {category: MapCategoryConfiguredPolicy},
	"sb_tc_insrc4":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_insrc6":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsrc4":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsrc6":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_insmac":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_exsmac":    {category: MapCategoryConfiguredPolicy},
	"sb_tc_lport":     {category: MapCategoryConfiguredPolicy},
	"sb_tc_sport":     {category: MapCategoryConfiguredPolicy},
	"sb_sh_inmac":     {category: MapCategoryConfiguredPolicy},
	"sb_sh_exmac":     {category: MapCategoryConfiguredPolicy},
	"sb_sh_port":      {category: MapCategoryConfiguredPolicy},
}

func metadataForMapName(name string) mapMetadata {
	if metadata, ok := configuredPolicyMapMetadata[name]; ok {
		metadata.evictionMode = mapEvictionNone
		return metadata
	}
	metadata := mapMetadata{category: MapCategoryRuntime, evictionMode: mapEvictionNone}
	switch name {
	case "sb_tc_rfrag", "sb_cg_recover", "sb_cg_tcp", "sb_cg_tcp_peer", "sb_cg_flow", "sb_sh_bypass":
		metadata.evictionMode = mapEvictionLRUSafeCache
	}
	switch name {
	case "sb_self_sockets", "sb_cg_sock_byp", "sb_cg_tcp", "sb_cg_tcp_peer", "sb_cg_sk_peer", "sb_cg_udp", "sb_cg_token", "sb_cg_token_rev", "sb_cg_peer", "sb_tc_assign", "sb_tc_return", "sb_sh_orig", "sb_sh_token":
		metadata.admissionCritical = true
	}
	return metadata
}

type MapOccupancyReport struct {
	Status string         `json:"status"`
	Maps   []MapOccupancy `json:"maps"`
	Error  string         `json:"error,omitempty"`
}

// InspectMapOccupancy enumerates only maps owned by sing-ebpf (sb_ prefix).
// It is deliberately an on-demand operation: callers should invoke it from a
// user-facing diagnostic command, never from a watchdog or data-plane path.
func InspectMapOccupancy() MapOccupancyReport {
	report := MapOccupancyReport{Status: "pass", Maps: make([]MapOccupancy, 0)}
	var id CiliumEBPF.MapID
	for {
		next, err := CiliumEBPF.MapGetNextID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			report.Error = err.Error()
			report.Status = "unknown"
			break
		}
		id = next
		m, err := CiliumEBPF.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := m.Info()
		if infoErr != nil || info == nil || !strings.HasPrefix(info.Name, "sb_") {
			_ = m.Close()
			continue
		}
		report.Maps = append(report.Maps, inspectMapOccupancy(m, id, info))
		_ = m.Close()
	}
	sort.Slice(report.Maps, func(i, j int) bool { return report.Maps[i].Name < report.Maps[j].Name })
	if report.Error == "" {
		report.Status = mapOccupancyStatus(report.Maps)
	}
	return report
}

func inspectMapOccupancy(m *CiliumEBPF.Map, id CiliumEBPF.MapID, info *CiliumEBPF.MapInfo) MapOccupancy {
	metadata := metadataForMapName(info.Name)
	item := MapOccupancy{ID: id, Name: info.Name, Category: metadata.category, Type: info.Type.String(),
		MaxEntries: info.MaxEntries, KeySize: info.KeySize, ValueSize: info.ValueSize, Flags: info.Flags,
		OccupancyMode: "not_applicable", EvictionMode: metadata.evictionMode, AdmissionCritical: metadata.admissionCritical}
	if !occupancySupported(info.Type) {
		item.Pressure = "not_applicable"
		return item
	}
	item.OccupancyMode = "exact_scan"
	item.Supported = true
	var err error
	item.Entries, err = countMapKeys(m, info.KeySize, info.MaxEntries)
	if err != nil {
		item.Error = err.Error()
	}
	item.Pressure = mapPressure(item.Category, item.Entries, item.MaxEntries, item.Error != "")
	return item
}

func mapOccupancyStatus(maps []MapOccupancy) string {
	status := "pass"
	for _, item := range maps {
		if item.Pressure == "degraded" || item.Pressure == "recovery_failed" {
			return "degraded"
		} else if item.Pressure == "unavailable" {
			if status == "pass" {
				status = "unknown"
			}
		} else if item.Pressure == "warning" {
			status = "warning"
		}
	}
	return status
}

func mapPressure(category MapCategory, entries, maxEntries uint32, failed bool) string {
	if failed {
		return "recovery_failed"
	}
	if category == MapCategoryConfiguredPolicy {
		return "configured"
	}
	if maxEntries == 0 {
		return "unknown"
	}
	ratio := float64(entries) / float64(maxEntries)
	switch {
	case ratio >= 0.95:
		return "degraded"
	case ratio >= 0.85:
		return "warning"
	default:
		return "healthy"
	}
}

var errMapKeyIterationAborted = errors.New("map key iteration aborted")

func countMapKeys(m *CiliumEBPF.Map, keySize uint32, maxEntries uint32) (uint32, error) {
	key := make([]byte, keySize)
	next := make([]byte, keySize)
	err := m.NextKey(nil, &next)
	var entries uint32
	for err == nil {
		if entries >= maxEntries {
			return entries, errMapKeyIterationAborted
		}
		entries++
		copy(key, next)
		err = m.NextKey(key, &next)
	}
	if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		return entries, nil
	}
	return entries, err
}

func occupancySupported(typ CiliumEBPF.MapType) bool {
	switch typ {
	case CiliumEBPF.Hash, CiliumEBPF.LRUHash, CiliumEBPF.LPMTrie:
		return true
	default:
		return false
	}
}
