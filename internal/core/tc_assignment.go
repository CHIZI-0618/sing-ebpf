//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type tcAssignKey struct {
	Family             uint8
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
	Reserved           uint16
	InterfaceIndex     uint32
	SourceAddress      [16]byte
	DestinationAddress [16]byte
}

type tcAssignmentClaim struct {
	SocketCookie uint64
	Generation   uint32
	State        uint32
}

const (
	tcAssignmentClaimPublish uint32 = 1
	tcAssignmentClaimRetire  uint32 = 2
)

type TCAssignment struct {
	SocketCookie      uint64
	LastSeenNS        uint64
	InterfaceIndex    uint32
	SourceMAC         MACAddress
	Path              uint8
	SourceMACValid    uint8
	Generation        uint32
	NetworkGeneration uint32
	Reserved          [4]byte
}

// TCFlowSweepResult describes one bounded cleanup pass. Entries are
// removed after their kernel timestamp exceeds maxIdle and an immediate
// value/generation recheck still matches. The per-map scan budget also applies
// on batch-capable kernels; Complete covers assignment, return and fragments.
type TCFlowSweepResult struct {
	ReturnUsage      MapUsage
	ReturnUsageKnown bool
	ReturnScanned    uint32
	ReturnRemoved    uint32
	Usage            MapUsage
	Scanned          uint32
	Removed          uint32
	Complete         bool
	UsageKnown       bool
	Pressure         bool
	Failure          string
	FailureMap       string
	Missing          uint32
	Superseded       uint32
	InFlight         uint32
}

const (
	TCFlowSweepFailureClosed     = "closed"
	TCFlowSweepFailureScan       = "scan"
	TCFlowSweepFailureLookup     = "lookup"
	TCFlowSweepFailureDelete     = "delete"
	TCFlowSweepFailureRetirement = "retirement_failed"
)

type tcAssignmentSweepEntry struct {
	key   tcAssignKey
	value TCAssignment
}

// tcAssignmentStore owns the kernel assignment map and all userspace state
// needed to inspect it. Keeping the scan cursor, candidate buffer and removal
// accounting with the map prevents the TC runtime from accumulating flow-store
// details as return routes and fragment state are refactored next.
type tcAssignmentStore struct {
	mapFD        int
	capacity     uint32
	sweepAccess  sync.Mutex
	sweepRemoved uint32
	sweepScratch mapScanScratch[tcAssignKey, TCAssignment]
	candidates   []tcAssignmentSweepEntry
}

func makeTCAssignKey(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32) (tcAssignKey, error) {
	var key tcAssignKey
	if !source.IsValid() || !destination.IsValid() || source.Addr().Is4() != destination.Addr().Is4() {
		return key, E.New("invalid TC eBPF assignment tuple")
	}
	key.Protocol = protocol
	key.SourcePort = source.Port()
	key.DestinationPort = destination.Port()
	key.InterfaceIndex = interfaceIndex
	if source.Addr().Is4() {
		key.Family = addressFamilyIPv4
		source4 := source.Addr().As4()
		destination4 := destination.Addr().As4()
		copy(key.SourceAddress[:4], source4[:])
		copy(key.DestinationAddress[:4], destination4[:])
	} else {
		key.Family = addressFamilyIPv6
		key.SourceAddress = source.Addr().As16()
		key.DestinationAddress = destination.Addr().As16()
	}
	return key, nil
}

func (b *TCBackend) LookupAssignment(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, remove bool) (TCAssignment, error) {
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		return TCAssignment{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCAssignment{}, errBackendClosed
	}
	var assignment TCAssignment
	if err = lookupMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&key), unsafe.Pointer(&assignment)); err != nil {
		return TCAssignment{}, err
	}
	if assignment.NetworkGeneration != b.control.NetworkGeneration {
		return TCAssignment{}, unix.ENOENT
	}
	if remove {
		_ = deleteMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&key))
	}
	return assignment, nil
}

// RemoveAssignmentIfMatch removes one assignment only when its incarnation
// still belongs to the closing session. The retirement claim fences the value
// between the first lookup and the conditional delete.
func (b *TCBackend) RemoveAssignmentIfMatch(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, expected TCAssignment) (bool, error) {
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		return false, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return false, errBackendClosed
	}
	var current TCAssignment
	if err = lookupMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&key), unsafe.Pointer(&current)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if !sameTCAssignment(current, expected) {
		return false, nil
	}
	claimMap := b.runtime.maps["tc_assignment_claim"]
	if claimMap == nil {
		return false, E.New("TC assignment claim map is unavailable")
	}
	claim := tcAssignmentClaim{SocketCookie: current.SocketCookie, Generation: current.Generation, State: tcAssignmentClaimRetire}
	if err = claimMap.Update(&key, &claim, CiliumEBPF.UpdateNoExist); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, err
	}
	defer claimMap.Delete(&key)
	var fenced TCAssignment
	if err = lookupMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&key), unsafe.Pointer(&fenced)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if !sameTCAssignment(fenced, expected) {
		return false, nil
	}
	if err = deleteMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&key)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func sameTCAssignment(left, right TCAssignment) bool {
	left.LastSeenNS, right.LastSeenNS = 0, 0
	return left == right
}

// SweepFlows performs a bounded cleanup pass for TC assignments and then
// delegates return-route and fragment cleanup to the paired stores.
func (b *TCBackend) SweepFlows(maxIdle time.Duration, fallbackBudget uint32) (TCFlowSweepResult, error) {
	if b == nil {
		return TCFlowSweepResult{Failure: TCFlowSweepFailureClosed}, errBackendClosed
	}
	if maxIdle <= 0 || fallbackBudget == 0 {
		return TCFlowSweepResult{}, unix.EINVAL
	}
	maxIdle = max(maxIdle, 2*time.Second)
	b.flowStore.assignment.sweepAccess.Lock()
	defer b.flowStore.assignment.sweepAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_assignment"] == nil || b.runtime.maps["tc_assignment_claim"] == nil {
		return TCFlowSweepResult{Failure: TCFlowSweepFailureClosed}, errBackendClosed
	}
	result := TCFlowSweepResult{Usage: MapUsage{Capacity: b.flowStore.assignment.capacity}, FailureMap: "sb_tc_assign"}
	now := monotonicNowNS()
	staleBefore := now - min(now, uint64(maxIdle))
	b.flowStore.assignment.candidates = b.flowStore.assignment.candidates[:0]
	scan, err := b.flowStore.assignment.sweepScratch.scan(b.runtime.maps["tc_assignment"], b.flowStore.assignment.capacity, fallbackBudget,
		func(key tcAssignKey, value TCAssignment) {
			if value.NetworkGeneration != b.control.NetworkGeneration || (value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore) {
				b.flowStore.assignment.candidates = append(b.flowStore.assignment.candidates, tcAssignmentSweepEntry{key: key, value: value})
			}
		})
	if err != nil {
		result.Failure = TCFlowSweepFailureScan
		return result, err
	}
	result.Scanned, result.Complete = scan.Scanned, scan.Complete
	if scan.Restarted {
		b.flowStore.assignment.sweepRemoved = 0
	}
	for _, candidate := range b.flowStore.assignment.candidates {
		var current TCAssignment
		if err = lookupMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&candidate.key), unsafe.Pointer(&current)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				result.Missing++
				continue
			}
			result.Failure = TCFlowSweepFailureLookup
			return result, err
		}
		if current.Generation != candidate.value.Generation || !sameTCAssignment(current, candidate.value) {
			result.Superseded++
			continue
		}
		if current.NetworkGeneration == b.control.NetworkGeneration && current.LastSeenNS > staleBefore {
			result.InFlight++
			continue
		}
		claimMap := b.runtime.maps["tc_assignment_claim"]
		claim := tcAssignmentClaim{SocketCookie: candidate.value.SocketCookie, Generation: candidate.value.Generation, State: tcAssignmentClaimRetire}
		if claimErr := claimMap.Update(&candidate.key, &claim, CiliumEBPF.UpdateNoExist); claimErr != nil {
			if errors.Is(claimErr, unix.EEXIST) {
				result.InFlight++
				continue
			}
			result.Failure = TCFlowSweepFailureLookup
			return result, claimErr
		}
		var fenced TCAssignment
		if err = lookupMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&candidate.key), unsafe.Pointer(&fenced)); err != nil {
			_ = claimMap.Delete(&candidate.key)
			if errors.Is(err, unix.ENOENT) {
				result.Missing++
				continue
			}
			result.Failure = TCFlowSweepFailureLookup
			return result, err
		}
		if !sameTCAssignment(fenced, candidate.value) || (fenced.NetworkGeneration == b.control.NetworkGeneration && fenced.LastSeenNS > staleBefore) {
			_ = claimMap.Delete(&candidate.key)
			result.InFlight++
			continue
		}
		if err = deleteMap(b.flowStore.assignment.mapFD, unsafe.Pointer(&candidate.key)); err != nil && !errors.Is(err, unix.ENOENT) {
			_ = claimMap.Delete(&candidate.key)
			result.Failure = TCFlowSweepFailureDelete
			return result, err
		}
		_ = claimMap.Delete(&candidate.key)
		result.Removed++
		b.flowStore.assignment.sweepRemoved++
	}
	if result.Complete {
		result.Usage.Entries = scan.Entries - min(scan.Entries, b.flowStore.assignment.sweepRemoved)
		b.flowStore.assignment.sweepRemoved = 0
		result.UsageKnown = true
		result.Pressure = uint64(result.Usage.Entries)*100 >= uint64(result.Usage.Capacity)*70
	}
	if err = b.sweepReturnRoutesLocked(max(maxIdle, time.Second), fallbackBudget, &result); err != nil {
		return result, err
	}
	if result.Failure == "" {
		result.FailureMap = ""
	}
	return result, nil
}
