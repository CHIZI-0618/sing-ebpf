//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"net/netip"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
)

// newTestAssignmentBackend builds a backend whose only runtime is a real
// assignment map, which is what the lookup path reads and writes.
func newTestAssignmentBackend(t *testing.T) *TCBackend {
	t.Helper()
	assignmentMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.Hash,
		Flags:      bpfFlagNoPrealloc,
		KeySize:    uint32(unsafe.Sizeof(tcAssignKey{})),
		ValueSize:  uint32(unsafe.Sizeof(TCAssignment{})),
		MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("cannot create an assignment map: %v", err)
	}
	t.Cleanup(func() { _ = assignmentMap.Close() })
	backend := &TCBackend{}
	backend.runtime = &tcRuntime{maps: map[string]*CiliumEBPF.Map{"tc_assignment": assignmentMap}}
	returnMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type: CiliumEBPF.Hash, KeySize: uint32(unsafe.Sizeof(tcAssignKey{})),
		ValueSize: uint32(unsafe.Sizeof(tcReturnValue{})), MaxEntries: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = returnMap.Close() })
	backend.runtime.maps["tc_return"] = returnMap
	backend.assignmentMapFD = assignmentMap.FD()
	return backend
}

// writeTestAssignment writes through the same raw map helper the programs and
// the lookup path use, so the value is laid out the way the map expects rather
// than the way a marshaller would pack it.
func writeTestAssignment(
	t *testing.T,
	backend *TCBackend,
	protocol uint8,
	source, destination netip.AddrPort,
	interfaceIndex uint32,
	value TCAssignment,
) {
	t.Helper()
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		t.Fatalf("build the assignment key: %v", err)
	}
	if err = updateMap(backend.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatalf("write the assignment: %v", err)
	}
}

// TestLookupAssignmentKeyIncludesInterfaceIndex covers what the interface index
// does in the lookup key: an entry is found under the index it was written for,
// and not under a different one.
//
// It says nothing about how long an entry lives or about what happens to entries
// when an interface goes away.
func TestLookupAssignmentKeyIncludesInterfaceIndex(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41000")
	destination := netip.MustParseAddrPort("10.0.0.1:53")
	const reusedIndex = 5

	// An entry written for one interface index.
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, reusedIndex, TCAssignment{
		SocketCookie:   0x1111,
		InterfaceIndex: reusedIndex,
		SourceMAC:      MACAddress{0xaa, 0, 0, 0, 0, 1},
		Path:           TCPathShared,
		SourceMACValid: 1,
	})

	// The same flow and the same index read the same key.
	assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex, false)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x1111 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}

	// A different index is a different key.
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, reusedIndex+1, false); err == nil {
		t.Fatal("an assignment was found under an index it was not written for")
	}
}

// TestLookupAssignmentRemovesEntryOnRequest covers the removing form of the
// lookup, which is the one the TCP path uses: a successful read with remove set
// takes the entry with it, and a second read of the same key finds nothing.
//
// It covers that one call. It does not say what else may write the same key
// before or after.
func TestLookupAssignmentRemovesEntryOnRequest(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41001")
	destination := netip.MustParseAddrPort("10.0.0.1:443")

	writeTestAssignment(t, backend, ProtocolTCP, source, destination, 0, TCAssignment{
		SocketCookie: 0x2222,
		Path:         TCPathDelivery,
	})

	assignment, err := backend.LookupAssignment(ProtocolTCP, source, destination, 0, true)
	if err != nil {
		t.Fatalf("lookup the assignment: %v", err)
	}
	if assignment.SocketCookie != 0x2222 {
		t.Fatalf("assignment = %+v, want the entry that was written", assignment)
	}
	if _, err = backend.LookupAssignment(ProtocolTCP, source, destination, 0, false); err == nil {
		t.Fatal("the entry survived a lookup that was asked to remove it")
	}
}

// TestLookupAssignmentKeepsEntryWhenNotAsked covers the other form, which is the
// one the UDP path uses: reading without remove leaves the entry in place, so
// the same key can be read again.
//
// It covers the lookup only. Nothing here is a statement about when entries are
// otherwise removed.
func TestLookupAssignmentKeepsEntryWhenNotAsked(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("10.0.0.2:41002")
	destination := netip.MustParseAddrPort("10.0.0.1:53")

	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 7, TCAssignment{
		SocketCookie: 0x3333,
		Path:         TCPathShared,
	})

	for range 3 {
		assignment, err := backend.LookupAssignment(ProtocolUDP, source, destination, 7, false)
		if err != nil {
			t.Fatalf("lookup the assignment: %v", err)
		}
		if assignment.SocketCookie != 0x3333 {
			t.Fatalf("assignment = %+v, want the entry that was written", assignment)
		}
	}
}

func TestRemoveAssignmentIfMatch(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	expected := TCAssignment{SocketCookie: 0x4444, InterfaceIndex: 17, Path: TCPathShared}
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, expected)

	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, TCAssignment{SocketCookie: 0x9999}); err != nil {
		t.Fatalf("mismatched removal: %v", err)
	} else if removed {
		t.Fatal("mismatched assignment was removed")
	}
	if _, err := backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err != nil {
		t.Fatalf("mismatched removal deleted assignment: %v", err)
	}

	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, expected); err != nil {
		t.Fatalf("matching removal: %v", err)
	} else if !removed {
		t.Fatal("matching assignment was not removed")
	}
	if _, err := backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err == nil {
		t.Fatal("matching removal left assignment in map")
	}
}

// TestRemoveAssignmentIfMatchFollowsActivityRefresh covers a session that read
// its assignment and closes after more packets: the programs only refreshed
// LastSeenNS, so the entry is still the session's. Once another session
// rewrote it under a new Generation, it is left alone.
func TestRemoveAssignmentIfMatchFollowsActivityRefresh(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	source := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	written := TCAssignment{SocketCookie: 0x4444, LastSeenNS: 100, InterfaceIndex: 17, Path: TCPathShared, Generation: 1}
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, written)
	expected, err := backend.LookupAssignment(ProtocolUDP, source, destination, 17, false)
	if err != nil {
		t.Fatal(err)
	}

	replaced := written
	replaced.LastSeenNS = 300
	replaced.Generation = 2
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, replaced)
	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, expected); err != nil {
		t.Fatalf("removal after replacement: %v", err)
	} else if removed {
		t.Fatal("a newer generation of the assignment was removed")
	}

	refreshed := written
	refreshed.LastSeenNS = 200
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, refreshed)
	if removed, err := backend.RemoveAssignmentIfMatch(ProtocolUDP, source, destination, 17, expected); err != nil {
		t.Fatalf("removal after refresh: %v", err)
	} else if !removed {
		t.Fatal("an assignment whose activity was refreshed was not removed")
	}
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err == nil {
		t.Fatal("refreshed assignment remains in map")
	}
}

func TestSweepAssignmentsRemovesOnlyUnchangedStaleEntries(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	backend.assignmentCapacity = 64
	source := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	key, err := makeTCAssignKey(ProtocolUDP, source, destination, 17)
	if err != nil {
		t.Fatal(err)
	}
	expected := TCAssignment{SocketCookie: 0x4444, InterfaceIndex: 17, Path: TCPathShared}
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, expected)
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err != nil {
		t.Fatal(err)
	}
	value := expected
	// A freshly booted test VM may not have one minute of uptime. Use a
	// nonzero boot-time timestamp after the minimum cleanup grace instead
	// of subtracting into an unsigned timestamp in the future.
	if now := monotonicNowNS(); now <= uint64(2*time.Second) {
		time.Sleep(2*time.Second - time.Duration(now) + time.Millisecond)
	}
	value.LastSeenNS = 1
	if err = updateMap(backend.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatal(err)
	}

	result, err := backend.SweepAssignments(time.Second, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 1 || !result.Complete || !result.UsageKnown || result.Failure != "" {
		t.Fatalf("unexpected sweep result: %+v", result)
	}
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err == nil {
		t.Fatal("stale assignment remains in map")
	}
}

func TestSweepAssignmentsPreservesCoalescedActivity(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	backend.assignmentCapacity = 64
	source := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	now := monotonicNowNS()
	value := TCAssignment{LastSeenNS: max(1, now-min(now, uint64(time.Second))), Generation: 42, InterfaceIndex: 17, Path: TCPathShared}
	writeTestAssignment(t, backend, ProtocolUDP, source, destination, 17, value)
	key, err := makeTCAssignKey(ProtocolUDP, destination, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	returnValue := tcReturnValue{LastSeenNS: value.LastSeenNS, Generation: 42, InterfaceIndex: 17}
	if err = backend.runtime.maps["tc_return"].Put(key, returnValue); err != nil {
		t.Fatal(err)
	}

	// A caller's subsecond timeout must not mistake the native one-second
	// write coalescing window for inactivity, for either map.
	result, err := backend.SweepAssignments(time.Nanosecond, 64)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 0 || result.ReturnRemoved != 0 || !result.UsageKnown || !result.ReturnUsageKnown {
		t.Fatalf("coalesced activity was reclaimed: %+v", result)
	}
	if _, err = backend.LookupAssignment(ProtocolUDP, source, destination, 17, false); err != nil {
		t.Fatal(err)
	}
	if err = backend.runtime.maps["tc_return"].Lookup(key, &returnValue); err != nil {
		t.Fatal(err)
	}
}

func TestSweepAssignmentsPreservesReturnFailureMap(t *testing.T) {
	backend := newTestAssignmentBackend(t)
	backend.assignmentCapacity = 64
	delete(backend.runtime.maps, "tc_return")

	result, err := backend.SweepAssignments(time.Second, 64)
	if err == nil {
		t.Fatal("sweep without the return map succeeded")
	}
	if result.Failure != TCAssignmentSweepFailureClosed || result.FailureMap != "sb_tc_return" {
		t.Fatalf("sweep failure = %+v, want closed sb_tc_return", result)
	}
}
