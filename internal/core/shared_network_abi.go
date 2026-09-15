//go:build with_ebpf && (linux || android)

package core

import (
	"math"
	"net"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const sharedNetworkTCPReleaseGrace = time.Second

type SharedPacketRewriteConfig struct {
	ListenerPort uint16
	EnableTCP    bool
	EnableUDP    bool
	RedirectIPv4 netip.Prefix
	RedirectIPv6 netip.Prefix
	Policy       CompiledPolicy
	MapCapacity  SharedPacketRewriteMapCapacity
	UDPTimeout   time.Duration
	// ICMPEchoReply loads a ICMPEchoReplyBackend (see icmp_echo_reply_backend.go)
	// alongside this one, answering ICMP Echo Request to the ForceIntercept prefixes
	// already in Policy the same way TCBackend's shared socket_assign path
	// already does. IPv6 coverage follows RedirectIPv6.IsValid(), the same
	// signal this config already uses to mean "IPv6 is enabled for this
	// shared backend" -- not a second, independently-set toggle.
	ICMPEchoReply bool
}

type sharedNetworkMACKey struct {
	Address  MACAddress
	Reserved [2]byte
}

type sharedPacketRewriteControl struct {
	Enabled                  uint32
	Flags                    uint32
	ListenerPort             uint16
	DNSMode                  DNSMode
	TokenIPv4Prefix          [4]byte
	TokenIPv4PrefixBits      uint8
	TokenIPv6PrefixBits      uint8
	Reserved2                [2]byte
	TokenIPv6Prefix          [16]byte
	UDPTimeoutSeconds        uint32
	ForceInterceptIPv4Prefix [4]byte
	ForceInterceptIPv4Mask   [4]byte
	ForceInterceptIPv6Prefix [16]byte
	ForceInterceptIPv6Mask   [16]byte
}

func sharedNetworkUDPTimeoutSeconds(timeout time.Duration) (uint32, error) {
	if timeout <= 0 {
		return 0, E.New("invalid shared packet-rewrite UDP timeout: ", timeout)
	}
	seconds := uint64(timeout / time.Second)
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds > math.MaxUint32 {
		return 0, E.New("shared packet-rewrite UDP timeout is too large: ", timeout)
	}
	return uint32(seconds), nil
}

type sharedNetworkListenerKey struct {
	Family       uint8
	Protocol     uint8
	ListenerPort uint16
	TokenAddr    [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type sharedNetworkOriginalKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	OriginalPort   uint16
	Reserved       uint16
	ClientAddr     [16]byte
	OriginalAddr   [16]byte
}

type sharedNetworkTokenValue struct {
	TokenAddr  [16]byte
	Generation uint64
	LastSeenNS uint64
	Reserved   uint64
}

type sharedNetworkOriginalValue struct {
	Family         uint8
	Protocol       uint8
	Port           uint16
	Addr           [16]byte
	InterfaceIndex uint32
	Generation     uint64
	SourceMAC      [6]byte
	Reserved2      [2]byte
}

type SharedPacketRewriteFlowHandle struct {
	originalKey sharedNetworkOriginalKey
	listenerKey sharedNetworkListenerKey
	generation  uint64
}

func (h *SharedPacketRewriteFlowHandle) InterfaceIndex() uint32 {
	if h == nil {
		return 0
	}
	return h.originalKey.InterfaceIndex
}

type SharedPacketRewriteSweepResult struct {
	Scanned  uint32
	Removed  uint32
	Retained uint32
	Usage    MapUsage
	Complete bool
}

const (
	sharedPacketRewriteFlagIPv4 = 1 << iota
	sharedPacketRewriteFlagIPv6
	sharedPacketRewriteFlagTCP
	sharedPacketRewriteFlagUDP
	_
	sharedPacketRewriteFlagHostIPv4
	sharedPacketRewriteFlagHostIPv6
	sharedPacketRewriteFlagBypassIPv4
	sharedPacketRewriteFlagBypassIPv6
	sharedPacketRewriteFlagIncludeSource
	sharedPacketRewriteFlagExcludeSource
	sharedPacketRewriteFlagIncludeSourceMAC
	sharedPacketRewriteFlagExcludeSourceMAC
	sharedPacketRewriteFlagBypassPrivateAddress
	sharedPacketRewriteFlagBypassFlowCache
	_
	sharedPacketRewriteFlagForceInterceptIPv4
	sharedPacketRewriteFlagForceInterceptIPv6
)

const sharedNetworkPolicyFlags = sharedPacketRewriteFlagHostIPv4 |
	sharedPacketRewriteFlagHostIPv6 |
	sharedPacketRewriteFlagBypassIPv4 |
	sharedPacketRewriteFlagBypassIPv6 |
	sharedPacketRewriteFlagIncludeSource |
	sharedPacketRewriteFlagExcludeSource |
	sharedPacketRewriteFlagIncludeSourceMAC |
	sharedPacketRewriteFlagExcludeSourceMAC |
	sharedPacketRewriteFlagBypassFlowCache

const sharedNetworkBypassFlowPolicyFlags = sharedPacketRewriteFlagBypassIPv4 |
	sharedPacketRewriteFlagBypassIPv6 |
	sharedPacketRewriteFlagIncludeSource |
	sharedPacketRewriteFlagExcludeSource |
	sharedPacketRewriteFlagIncludeSourceMAC |
	sharedPacketRewriteFlagExcludeSourceMAC

func sharedNetworkBypassFlowCacheRequired(flags uint32) bool {
	return flags&sharedNetworkBypassFlowPolicyFlags != 0
}

func makeSharedNetworkListenerKey(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (sharedNetworkListenerKey, error) {
	var key sharedNetworkListenerKey
	key.Protocol = protocol
	key.ListenerPort = tokenDestination.Port()
	key.ClientPort = client.Port()
	if err := encodeAddress(&key.Family, &key.TokenAddr, tokenDestination.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network redirect address")
	}
	var clientFamily uint8
	if err := encodeAddress(&clientFamily, &key.ClientAddr, client.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network client address")
	}
	if clientFamily != key.Family {
		return sharedNetworkListenerKey{}, E.New("shared-network client and redirect address families do not match")
	}
	return key, nil
}

func sharedNetworkOriginalAddress(value sharedNetworkOriginalValue) (netip.Addr, error) {
	return sharedNetworkAddress(value.Family, value.Addr)
}

func sharedNetworkAddress(family uint8, address [16]byte) (netip.Addr, error) {
	switch family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(address[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(address), nil
	default:
		return netip.Addr{}, E.New("invalid shared-network address family: ", family)
	}
}

func sharedNetworkOriginalMAC(value sharedNetworkOriginalValue) net.HardwareAddr {
	return append(net.HardwareAddr(nil), value.SourceMAC[:]...)
}

func makeSharedPacketRewriteFlowHandle(key sharedNetworkListenerKey, value sharedNetworkOriginalValue) SharedPacketRewriteFlowHandle {
	return SharedPacketRewriteFlowHandle{
		originalKey: sharedNetworkOriginalKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			OriginalPort:   value.Port,
			ClientAddr:     key.ClientAddr,
			OriginalAddr:   value.Addr,
		},
		listenerKey: key,
		generation:  value.Generation,
	}
}

func makeSharedPacketRewriteFlowHandleFromOriginal(
	key sharedNetworkOriginalKey,
	token [16]byte,
	listenerPort uint16,
	generation uint64,
) SharedPacketRewriteFlowHandle {
	return SharedPacketRewriteFlowHandle{
		originalKey: key,
		listenerKey: sharedNetworkListenerKey{
			Family: key.Family, Protocol: key.Protocol, ListenerPort: listenerPort,
			TokenAddr: token, ClientPort: key.ClientPort, ClientAddr: key.ClientAddr,
		},
		generation: generation,
	}
}
