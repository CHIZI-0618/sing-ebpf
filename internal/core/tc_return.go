//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

type tcReturnValue struct {
	LastSeenNS        uint64
	Generation        uint64
	InterfaceIndex    uint32
	Flags             uint32
	SourceMAC         MACAddress
	DestinationMAC    MACAddress
	NetworkGeneration uint32
}

const tcReturnRetiring uint32 = 1

type tcReturnReference struct {
	key        tcAssignKey
	generation uint64
}

// tcReturnStore owns tuple-preserving return routes, their consumer claims,
// and the bounded cleanup cursors for return and fragment maps.
type tcReturnStore struct {
	access          sync.Mutex
	references      map[tcReturnReference]uint32
	sweepRemoved    uint32
	sweepScratch    mapScanScratch[tcAssignKey, tcReturnValue]
	fragmentScratch mapScanScratch[tcAssignKey, tcReturnValue]
}

// TCReturnHandle pins a tuple-preserving return route for one consumer. Every
// successful acquire must be released once, after the consumer stops writing.
// It is opaque and cannot be shared between backends or reconstructed by callers.
type TCReturnHandle struct {
	reference tcReturnReference
	owner     *TCBackend
}

func (h TCReturnHandle) IsValid() bool { return h.owner != nil && h.reference.generation != 0 }
func (h TCReturnHandle) Release() {
	if h.owner != nil {
		h.owner.ReleaseReturnRoute(h)
	}
}

func (b *TCBackend) retainReturnRouteLocked(key tcAssignKey, value tcReturnValue) TCReturnHandle {
	if b.flowStore.returns.references == nil {
		b.flowStore.returns.references = make(map[tcReturnReference]uint32)
	}
	ref := tcReturnReference{key: key, generation: value.Generation}
	b.flowStore.returns.references[ref]++
	return TCReturnHandle{reference: ref, owner: b}
}

func (b *TCBackend) AcquireReturnRoute(protocol uint8, source, destination netip.AddrPort) (TCReturnHandle, error) {
	if b == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	key, err := makeTCAssignKey(protocol, destination, source, 0)
	if err != nil {
		return TCReturnHandle{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_return"] == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.flowStore.returns.access.Lock()
	defer b.flowStore.returns.access.Unlock()
	var value tcReturnValue
	if err = b.runtime.maps["tc_return"].Lookup(&key, &value); err != nil {
		return TCReturnHandle{}, err
	}
	if value.Generation == 0 {
		return TCReturnHandle{}, E.New("invalid TC return generation")
	}
	if value.NetworkGeneration&0x7fffffff != b.control.NetworkGeneration {
		return TCReturnHandle{}, unix.ENOENT
	}
	if value.NetworkGeneration&tcReturnRetiring != 0 {
		return TCReturnHandle{}, E.New("TC return route is retiring")
	}
	return b.retainReturnRouteLocked(key, value), nil
}

// AcquireReplyRoute allows a UDP consumer to reply from a different endpoint
// without changing a packet tuple (e.g. a DNS response selected by its router).
// The alias inherits only the already-pinned client's return path.
func (b *TCBackend) AcquireReplyRoute(original TCReturnHandle, source netip.AddrPort) (TCReturnHandle, error) {
	if b == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_return"] == nil {
		return TCReturnHandle{}, errBackendClosed
	}
	b.flowStore.returns.access.Lock()
	defer b.flowStore.returns.access.Unlock()
	ref := original.reference
	if original.owner != b || ref.key.Protocol != ProtocolUDP || b.flowStore.returns.references[ref] == 0 {
		return TCReturnHandle{}, E.New("TC return route is not retained")
	}
	client := netip.AddrFrom16(ref.key.DestinationAddress)
	if ref.key.Family == unix.AF_INET {
		client = netip.AddrFrom4([4]byte(ref.key.DestinationAddress[:4]))
	}
	key, err := makeTCAssignKey(ProtocolUDP, source, netip.AddrPortFrom(client, ref.key.DestinationPort), 0)
	if err != nil {
		return TCReturnHandle{}, err
	}
	returnMap := b.runtime.maps["tc_return"]
	var value tcReturnValue
	if err = returnMap.Lookup(&ref.key, &value); err != nil {
		return TCReturnHandle{}, err
	}
	if value.Generation != ref.generation {
		return TCReturnHandle{}, E.New("TC return route generation changed")
	}
	if value.NetworkGeneration&0x7fffffff != b.control.NetworkGeneration {
		return TCReturnHandle{}, unix.ENOENT
	}
	if value.NetworkGeneration&tcReturnRetiring != 0 {
		return TCReturnHandle{}, E.New("TC return route is retiring")
	}
	value.LastSeenNS = monotonicNowNS()
	value.Generation = value.LastSeenNS
	if err = returnMap.Update(&key, &value, CiliumEBPF.UpdateNoExist); err != nil && !errors.Is(err, unix.EEXIST) {
		return TCReturnHandle{}, err
	}
	var current tcReturnValue
	if err = returnMap.Lookup(&key, &current); err != nil {
		return TCReturnHandle{}, err
	}
	if current.NetworkGeneration&tcReturnRetiring != 0 {
		return TCReturnHandle{}, E.New("TC reply route is retiring")
	}
	if current.InterfaceIndex != value.InterfaceIndex || current.Flags != value.Flags || current.SourceMAC != value.SourceMAC || current.DestinationMAC != value.DestinationMAC {
		return TCReturnHandle{}, E.New("TC reply route belongs to another publisher")
	}
	return b.retainReturnRouteLocked(key, current), nil
}

func (b *TCBackend) ReleaseReturnRoute(handle TCReturnHandle) {
	if b == nil || handle.owner != b || !handle.IsValid() {
		return
	}
	b.flowStore.returns.access.Lock()
	defer b.flowStore.returns.access.Unlock()
	ref := handle.reference
	if count := b.flowStore.returns.references[ref]; count > 1 {
		b.flowStore.returns.references[ref] = count - 1
	} else {
		delete(b.flowStore.returns.references, ref)
	}
	// Keep the kernel record through FIN/ACK and delayed UDP replies. The
	// janitor reclaims it only after the activity grace, never on last release.
}

// Caller holds b.access. The reference lock serializes acquisition with idle
// cleanup, so a live consumer cannot lose its route to a maintenance pass.
func (b *TCBackend) sweepReturnRoutesLocked(maxIdle time.Duration, budget uint32, result *TCAssignmentSweepResult) error {
	result.FailureMap = "sb_tc_return"
	returnMap := b.runtime.maps["tc_return"]
	if returnMap == nil {
		result.Failure = TCAssignmentSweepFailureClosed
		return errBackendClosed
	}
	now := monotonicNowNS()
	staleBefore := now - min(now, uint64(maxIdle))
	type candidate struct {
		key   tcAssignKey
		value tcReturnValue
	}
	var candidates []candidate
	scan, err := b.flowStore.returns.sweepScratch.scan(returnMap, b.flowStore.assignment.capacity, budget, func(key tcAssignKey, value tcReturnValue) {
		if value.NetworkGeneration&0x7fffffff != b.control.NetworkGeneration ||
			(value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore) {
			candidates = append(candidates, candidate{key, value})
		}
	})
	if err != nil {
		result.Failure = TCAssignmentSweepFailureScan
		return err
	}
	result.ReturnScanned = scan.Scanned
	if scan.Restarted {
		b.flowStore.returns.sweepRemoved = 0
	}
	result.Complete = result.Complete && scan.Complete
	for _, entry := range candidates {
		// Acquisition is serialized only with this candidate's recheck/delete,
		// not with the entire map traversal.
		removed, failure, deleteErr := b.deleteIdleReturnRoute(returnMap, entry.key, entry.value)
		if deleteErr != nil {
			result.Failure = failure
			return deleteErr
		}
		if removed {
			result.ReturnRemoved++
			b.flowStore.returns.sweepRemoved++
		}
	}
	if scan.Complete {
		result.ReturnUsageKnown = true
		result.ReturnUsage = MapUsage{Capacity: b.flowStore.assignment.capacity, Entries: scan.Entries - min(scan.Entries, b.flowStore.returns.sweepRemoved)}
		b.flowStore.returns.sweepRemoved = 0
		result.Pressure = result.Pressure || uint64(result.ReturnUsage.Entries)*100 >= uint64(result.ReturnUsage.Capacity)*70
	}
	// Fragment cache entries have a fixed short lifetime and no userspace
	// readers. Reclaim expired entries without touching live flow references.
	if fragmentMap := b.runtime.maps["tc_return_frag"]; fragmentMap != nil {
		result.FailureMap = "sb_tc_rfrag"
		candidates = candidates[:0]
		scan, err = b.flowStore.returns.fragmentScratch.scan(fragmentMap, min(b.flowStore.assignment.capacity, 1024), budget, func(key tcAssignKey, value tcReturnValue) {
			if now > value.LastSeenNS && now-value.LastSeenNS > uint64(2*time.Second) {
				candidates = append(candidates, candidate{key, value})
			}
		})
		if err != nil {
			result.Failure = TCAssignmentSweepFailureScan
			return err
		}
		result.Complete = result.Complete && scan.Complete
		for _, entry := range candidates {
			var current tcReturnValue
			if err = fragmentMap.Lookup(&entry.key, &current); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				result.Failure = TCAssignmentSweepFailureLookup
				return err
			}
			if current == entry.value {
				if err = fragmentMap.Delete(&entry.key); err != nil && !errors.Is(err, unix.ENOENT) {
					result.Failure = TCAssignmentSweepFailureDelete
					return err
				}
			}
		}
	}
	return nil
}

func (b *TCBackend) deleteIdleReturnRoute(returnMap *CiliumEBPF.Map, key tcAssignKey, expected tcReturnValue) (bool, string, error) {
	b.flowStore.returns.access.Lock()
	defer b.flowStore.returns.access.Unlock()
	if b.flowStore.returns.references[tcReturnReference{key, expected.Generation}] != 0 {
		return false, "", nil
	}
	var current tcReturnValue
	if err := returnMap.Lookup(&key, &current); errors.Is(err, unix.ENOENT) {
		return false, "", nil
	} else if err != nil {
		return false, TCAssignmentSweepFailureLookup, err
	}
	if current != expected {
		return false, "", nil
	}
	current.NetworkGeneration |= tcReturnRetiring
	if err := returnMap.Update(&key, &current, CiliumEBPF.UpdateAny); err != nil {
		return false, TCAssignmentSweepFailureLookup, err
	}
	var fenced tcReturnValue
	if err := returnMap.Lookup(&key, &fenced); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, "", nil
		}
		return false, TCAssignmentSweepFailureLookup, err
	}
	if !sameTCReturnRoute(fenced, expected) || fenced.NetworkGeneration&tcReturnRetiring == 0 {
		return false, "", nil
	}
	if err := returnMap.Delete(&key); errors.Is(err, unix.ENOENT) {
		return false, "", nil
	} else if err != nil {
		return false, TCAssignmentSweepFailureDelete, err
	}
	return true, "", nil
}

func sameTCReturnRoute(left, right tcReturnValue) bool {
	left.LastSeenNS, right.LastSeenNS = 0, 0
	left.NetworkGeneration, right.NetworkGeneration = 0, 0
	return left == right
}
