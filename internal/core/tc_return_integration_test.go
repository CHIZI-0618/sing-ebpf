//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCReturnRouteLifetimeIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC return-route pinning and idle cleanup")
	b := newTestAssignmentBackend(t)
	returnMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 44, ValueSize: uint32(unsafe.Sizeof(tcReturnValue{})), MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer returnMap.Close()
	b.runtime.maps["tc_return"] = returnMap
	b.assignment.capacity = 2
	source, destination := netip.MustParseAddrPort("192.0.2.2:41000"), netip.MustParseAddrPort("203.0.113.10:9681")
	key, _ := makeTCAssignKey(ProtocolUDP, destination, source, 0)
	value := tcReturnValue{LastSeenNS: 1, Generation: 42, InterfaceIndex: 7, Flags: 1}
	if err = returnMap.Put(key, value); err != nil {
		t.Fatal(err)
	}
	first, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := b.AcquireReplyRoute(first, netip.MustParseAddrPort("203.0.113.20:8567"))
	if err != nil {
		t.Fatal(err)
	}
	foreign := &TCBackend{}
	foreign.ReleaseReturnRoute(first)
	first.Release()
	if b.returns.references[second.reference] != 1 {
		t.Fatal("wrong reference ownership/count")
	}
	// A full map rejects new flows without evicting either retained route.
	thirdKey := key
	thirdKey.SourcePort++
	if err = returnMap.Put(thirdKey, value); err == nil {
		t.Fatal("full HASH admitted an extra route")
	}
	result := TCAssignmentSweepResult{Complete: true, UsageKnown: true}
	if err = b.sweepReturnRoutesLocked(time.Nanosecond, 16, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReturnRemoved != 0 || result.ReturnUsage.Entries != 2 || !result.Pressure {
		t.Fatalf("pinned sweep: %+v", result)
	}
	second.Release()
	alias.Release()
	result = TCAssignmentSweepResult{Complete: true, UsageKnown: true}
	if err = b.sweepReturnRoutesLocked(time.Nanosecond, 16, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReturnRemoved != 2 {
		t.Fatalf("released sweep: %+v", result)
	}
	if err = returnMap.Lookup(key, &value); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("released route retained: %v", err)
	}
	// Reusing a tuple creates a new generation; releasing a stale handle must
	// not decrement the new consumer's reference.
	value.Generation = 43
	if err = returnMap.Put(key, value); err != nil {
		t.Fatal(err)
	}
	current, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
	if b.returns.references[current.reference] != 1 {
		t.Fatal("stale generation released current owner")
	}
	current.Release()
}
