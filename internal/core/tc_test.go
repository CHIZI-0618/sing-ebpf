//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestTCABI(t *testing.T) {
	if size := unsafe.Sizeof(tcReturnValue{}); size != 40 {
		t.Fatalf("unexpected TC return value size: %d", size)
	}
	if offset := unsafe.Offsetof(tcReturnValue{}.InterfaceIndex); offset != 16 {
		t.Fatalf("unexpected TC return ifindex offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcReturnValue{}.DestinationMAC); offset != 30 {
		t.Fatalf("unexpected TC return MAC offset: %d", offset)
	}
	if size := unsafe.Sizeof(tcControl{}); size != 40 {
		t.Fatalf("unexpected TC control size: %d", size)
	}
	if offset := unsafe.Offsetof(tcControl{}.RoutingMark); offset != 12 {
		t.Fatalf("unexpected TC routing mark offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.DeliveryInterface); offset != 8 {
		t.Fatalf("unexpected TC delivery interface offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.ListenerPort); offset != 16 {
		t.Fatalf("unexpected TC listener port offset: %d", offset)
	}
	if offset := unsafe.Offsetof(tcControl{}.NetworkGeneration); offset != 20 {
		t.Fatalf("unexpected TC network generation offset: %d", offset)
	}
	if size := unsafe.Sizeof(tcAssignKey{}); size != 44 {
		t.Fatalf("unexpected TC assignment key size: %d", size)
	}
	if size := unsafe.Sizeof(TCAssignment{}); size != 40 {
		t.Fatalf("unexpected TC assignment value size: %d", size)
	}
	if size := unsafe.Sizeof(tcAssignmentClaim{}); size != 16 {
		t.Fatalf("unexpected TC assignment claim size: %d", size)
	}
	if offset := unsafe.Offsetof(tcAssignmentClaim{}.State); offset != 12 {
		t.Fatalf("unexpected TC assignment claim state offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.SocketCookie); offset != 0 {
		t.Fatalf("unexpected TC assignment socket cookie offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.LastSeenNS); offset != 8 {
		t.Fatalf("unexpected TC assignment last-seen offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.InterfaceIndex); offset != 16 {
		t.Fatalf("unexpected TC assignment interface index offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.NetworkGeneration); offset != 32 {
		t.Fatalf("unexpected TC assignment network generation offset: %d", offset)
	}
	if offset := unsafe.Offsetof(TCAssignment{}.Reserved); offset != 36 {
		t.Fatalf("unexpected TC assignment reserved offset: %d", offset)
	}
}

func TestTCReturnRetirementUsesReservedGenerationBit(t *testing.T) {
	if tcReturnRetiring != ^networkGenerationMask {
		t.Fatalf("retirement bit = %#x, want %#x", tcReturnRetiring, ^networkGenerationMask)
	}
	for _, generation := range []uint32{1, 2, 0x7fffffff} {
		if generation&tcReturnRetiring != 0 {
			t.Fatalf("valid generation %#x is classified as retiring", generation)
		}
	}
}

func TestSameTCAssignmentIgnoresOnlyActivity(t *testing.T) {
	base := TCAssignment{
		SocketCookie: 1, LastSeenNS: 10, InterfaceIndex: 2,
		SourceMAC: MACAddress{1, 2, 3, 4, 5, 6}, Path: TCPathShared, SourceMACValid: 1, Generation: 3,
	}
	refreshed := base
	refreshed.LastSeenNS = 20
	if !sameTCAssignment(base, refreshed) {
		t.Fatal("a refreshed activity timestamp made the assignment differ")
	}
	for name, change := range map[string]func(*TCAssignment){
		"socket cookie":    func(value *TCAssignment) { value.SocketCookie++ },
		"interface index":  func(value *TCAssignment) { value.InterfaceIndex++ },
		"source MAC":       func(value *TCAssignment) { value.SourceMAC[5]++ },
		"path":             func(value *TCAssignment) { value.Path = TCPathDelivery },
		"source MAC valid": func(value *TCAssignment) { value.SourceMACValid = 0 },
		"generation":       func(value *TCAssignment) { value.Generation++ },
	} {
		changed := base
		change(&changed)
		if sameTCAssignment(base, changed) {
			t.Fatalf("assignments that differ in %s matched", name)
		}
	}
}

func TestTCIPv6PathFlags(t *testing.T) {
	localFlags := tcFlags(TCConfig{EnableLocalIPv6: true}, CompiledPolicy{})
	if localFlags&tcFlagLocalIPv6 == 0 || localFlags&tcFlagSharedIPv6 != 0 {
		t.Fatalf("unexpected local IPv6 flags: %#x", localFlags)
	}
	sharedFlags := tcFlags(TCConfig{EnableSharedIPv6: true}, CompiledPolicy{})
	if sharedFlags&tcFlagLocalIPv6 != 0 || sharedFlags&tcFlagSharedIPv6 == 0 {
		t.Fatalf("unexpected shared IPv6 flags: %#x", sharedFlags)
	}
	hybridFlags := tcFlags(TCConfig{EnableLocalIPv6: true, EnableSharedIPv6: true}, CompiledPolicy{})
	if hybridFlags&(tcFlagLocalIPv6|tcFlagSharedIPv6) != tcFlagLocalIPv6|tcFlagSharedIPv6 {
		t.Fatalf("unexpected hybrid IPv6 flags: %#x", hybridFlags)
	}
}

func TestMakeTCAssignKey(t *testing.T) {
	for _, test := range []struct {
		source      string
		destination string
		family      uint8
	}{
		{"192.0.2.10:12345", "1.1.1.1:443", addressFamilyIPv4},
		{"[2001:db8::10]:12345", "[2606:4700:4700::1111]:443", addressFamilyIPv6},
	} {
		source := netip.MustParseAddrPort(test.source)
		destination := netip.MustParseAddrPort(test.destination)
		key, err := makeTCAssignKey(ProtocolTCP, source, destination, 17)
		if err != nil {
			t.Fatal(err)
		}
		if key.Family != test.family || key.Protocol != ProtocolTCP ||
			key.SourcePort != source.Port() || key.DestinationPort != destination.Port() || key.InterfaceIndex != 17 {
			t.Fatalf("unexpected TC assignment key: %+v", key)
		}
		if got := tcKeyAddress(key.Family, key.SourceAddress); got != source.Addr() {
			t.Fatalf("unexpected source address: %s", got)
		}
		if got := tcKeyAddress(key.Family, key.DestinationAddress); got != destination.Addr() {
			t.Fatalf("unexpected destination address: %s", got)
		}
	}
	if _, err := makeTCAssignKey(
		ProtocolUDP,
		netip.MustParseAddrPort("192.0.2.1:1"),
		netip.MustParseAddrPort("[2001:db8::1]:2"),
		0,
	); err == nil {
		t.Fatal("mixed address families were accepted")
	}
}

func tcKeyAddress(family uint8, address [16]byte) netip.Addr {
	if family == addressFamilyIPv4 {
		return netip.AddrFrom4([4]byte(address[:4]))
	}
	return netip.AddrFrom16(address)
}
