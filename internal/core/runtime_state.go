//go:build with_ebpf && (linux || android)

package core

import CiliumEBPF "github.com/cilium/ebpf"

// RuntimeProgram describes one active program owned by sing-ebpf.
type RuntimeProgram struct {
	ID       CiliumEBPF.ProgramID
	Name     string
	Type     CiliumEBPF.ProgramType
	MapCount int
	MapIDs   []CiliumEBPF.MapID
}

// RuntimeState is collected only for an explicit diagnostic request.
type RuntimeState struct {
	Programs      []RuntimeProgram
	ProgramsError error
	MapOccupancy  MapOccupancyReport
}

// InspectRuntimeState enumerates active sing-ebpf programs and maps without
// attaching, detaching, or otherwise changing the running data paths.
func InspectRuntimeState() RuntimeState {
	programs, err := probeActivePrograms()
	return RuntimeState{
		Programs:      programs,
		ProgramsError: err,
		MapOccupancy:  InspectMapOccupancy(),
	}
}
