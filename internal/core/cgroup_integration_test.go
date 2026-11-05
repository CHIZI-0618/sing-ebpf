//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

func TestCgroupProgramMatrixIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup eBPF program matrix")
	cgroupPath, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}

	tests := []struct {
		name       string
		tcp        bool
		udp        bool
		enableIPv6 bool
	}{
		{name: "tcp4", tcp: true},
		{name: "udp4", udp: true},
		{name: "tcp6", tcp: true, enableIPv6: true},
		{name: "udp6", udp: true, enableIPv6: true},
		{name: "tcp_udp_dual_stack", tcp: true, udp: true, enableIPv6: true},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, dedicated := createIntegrationCgroup(t, cgroupPath, index)
			backend, err := prepareCgroupIntegrationBackend(path, test.tcp, test.udp, test.enableIPv6)
			if err != nil {
				if cgroupIntegrationUnavailable(err) {
					t.Skipf("cgroup eBPF is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })

			if err = backend.LoadPrograms(uint16(41000 + index)); err != nil {
				if cgroupIntegrationUnavailable(err) {
					t.Skipf("cgroup program loading is unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if dedicated {
				if err = backend.Attach(); err != nil {
					if cgroupIntegrationUnavailable(err) {
						t.Skipf("cgroup program attach is unavailable: %v", err)
					}
					t.Fatal(err)
				}
			}
			assertCgroupProgramSet(t, backend)
			assertCgroupMapABI(t, backend)
			if test.tcp {
				assertCgroupTCPMapHandoff(t, backend)
			}
			if test.udp {
				assertCgroupUDPMapHandoff(t, backend)
				assertCgroupUDPReleaseObserverLoaded(t, backend)
			}
		})
	}
}

func TestCgroupInitialBypassCIDRCountTracksLoadedPolicy(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup initial bypass CIDR state")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, _ := createIntegrationCgroup(t, cgroupRoot, 150)
	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer selfBypassMap.Close()
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{
			Default: DecisionIntercept,
			DestinationCIDR: []CIDRDecision{
				{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: DecisionPass},
				{Prefix: netip.MustParsePrefix("2001:db8::/32"), Action: DecisionPass},
			},
		},
		Shared: ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableTCP:     true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer backend.Close()
	if ipv4, ipv6 := backend.BypassCIDRCount(); ipv4 != 1 || ipv6 != 1 {
		t.Fatalf("initial bypass CIDR count = %d/%d, want 1/1", ipv4, ipv6)
	}
}

func TestCgroupUDPRecoverySweepRemovesExpiredEntries(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup UDP recovery sweep")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, _ := createIntegrationCgroup(t, cgroupRoot, 151)
	backend, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer backend.Close()
	key, err := makeListenerLookupKey(ProtocolUDP, netip.MustParseAddrPort("127.128.0.7:41000"))
	if err != nil {
		t.Fatal(err)
	}
	value := originalDestinationValue{
		Family:       addressFamilyIPv4,
		Protocol:     ProtocolUDP,
		Port:         443,
		SocketCookie: 123,
		CreatedAtNS:  1,
	}
	address := netip.MustParseAddr("192.0.2.7").As4()
	copy(value.Addr[:4], address[:])
	if err = updateMap(backend.udpRecoveryMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatal(err)
	}
	var removed uint32
	var complete bool
	for pass := 0; pass < 8; pass++ {
		// Unsupported batch commands switch to the bounded per-key iterator
		// on the next maintenance pass; a single pass need not finish.
		result, err := backend.SweepUDPRecovery(time.Nanosecond, 1024)
		if err != nil {
			t.Fatal(err)
		}
		removed += result.Removed
		complete = result.Complete
		if complete {
			break
		}
	}
	if !complete || removed != 1 {
		t.Fatalf("recovery sweep complete=%v removed=%d, want true/1", complete, removed)
	}
	var current originalDestinationValue
	if err = lookupMap(backend.udpRecoveryMapFD, unsafe.Pointer(&key), unsafe.Pointer(&current)); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("expired recovery entry remained: %v", err)
	}
}

func TestCgroupUDPRecoverySweepAccountsAcrossPartialPasses(t *testing.T) {
	requireEBPFIntegration(t, "test bounded cgroup recovery accounting")
	m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type: CiliumEBPF.LRUHash, KeySize: uint32(unsafe.Sizeof(listenerLookupKey{})),
		ValueSize: uint32(unsafe.Sizeof(originalDestinationValue{})), MaxEntries: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	backend := &CgroupBackend{
		runtime:          &cgroupRuntime{maps: map[string]*CiliumEBPF.Map{"cgroup_udp_recovery": m}},
		udpRecoveryMapFD: m.FD(), mapCapacity: CgroupMapCapacity{UDPRedirect: 64},
	}
	backend.recovery.scratch.lookupSupport.mode.Store(mapBatchUnsupported)
	for port := uint16(41000); port < 41003; port++ {
		key, err := makeListenerLookupKey(ProtocolUDP, netip.AddrPortFrom(netip.MustParseAddr("127.128.0.1"), port))
		if err != nil {
			t.Fatal(err)
		}
		if err = m.Put(key, originalDestinationValue{CreatedAtNS: 1}); err != nil {
			t.Fatal(err)
		}
	}
	var removed uint32
	for pass := 0; pass < 8; pass++ {
		result, err := backend.SweepUDPRecovery(time.Nanosecond, 1)
		if err != nil {
			t.Fatal(err)
		}
		removed += result.Removed
		if result.Complete {
			if removed != 3 || result.Usage.Entries != 0 {
				t.Fatalf("removed=%d final usage=%+v, want 3/0", removed, result.Usage)
			}
			return
		}
	}
	t.Fatal("bounded recovery scan did not complete")
}

// TestCgroupUDPFlowCacheDoesNotOverrideUIDBypass exercises the real
// sendmsg4 hook. It first verifies an uncached direct socket, then plants a
// proxy action for a second socket's exact cookie/five-tuple and verifies that
// the configured UID bypass still wins. This is intentionally an integration
// test: a source-order assertion would not catch an object-generation or
// verifier regression.
func TestCgroupUDPFlowCacheDoesNotOverrideUIDBypass(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup UDP UID/cache precedence")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, cgroupRoot, 100)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	uid := uint32(os.Geteuid())
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{
			Default: DecisionPass,
			UID:     []UIDDecision{{Start: uid, End: uid, Action: DecisionIntercept}},
		},
		Shared: ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer selfBypassMap.Close()
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableUDP:     true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer backend.Close()
	const listenerPort = 41000
	if err = backend.LoadPrograms(listenerPort); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program loading is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program attach is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	moveCurrentProcessToCgroup(t, path, cgroupRoot)

	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	dnsTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Skipf("cannot reserve loopback DNS port for UID policy regression: %v", err)
	}
	defer dnsTarget.Close()
	token, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 128, 0, 1), Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)
	dnsTargetAddr := dnsTarget.LocalAddr().(*net.UDPAddr)

	// A new socket has no flow-cache entry and must reach the real target.
	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if _, err = direct.WriteToUDP([]byte("direct"), targetAddr); err != nil {
		t.Fatal(err)
	}
	assertUDPReceived(t, target, "direct")

	cached, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cached.Close()
	cookie, err := udpSocketCookie(cached)
	if err != nil {
		t.Fatal(err)
	}
	// Port 53 is intentional: respect_policy must evaluate UID before the
	// cached proxy action even when DNS interception is enabled.
	flowKey := udpFlowKey{SocketCookie: cookie, Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: uint16(dnsTargetAddr.Port)}
	copy(flowKey.Addr[:4], dnsTargetAddr.IP.To4())
	flowValue := udpFlowValue{
		Action:            udpFlowActionProxy,
		LastSeenSeconds:   uint32(time.Now().Unix()),
		NetworkGeneration: backend.networkGeneration,
		Listener: listenerLookupKey{
			Family:       addressFamilyIPv4,
			Protocol:     ProtocolUDP,
			ListenerPort: listenerPort,
		},
	}
	copy(flowValue.Listener.TokenAddr[:4], net.IPv4(127, 128, 0, 1).To4())
	if err = backend.runtime.maps["cgroup_udp_flow"].Update(&flowKey, &flowValue, CiliumEBPF.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err = cached.WriteToUDP([]byte("cached"), dnsTargetAddr); err != nil {
		t.Fatal(err)
	}
	assertUDPReceived(t, dnsTarget, "cached")
	assertUDPNotReceived(t, token)
}

// TestCgroupForceInterceptPrefixesIntegration requires every force-intercept
// prefix of a family to override a pass default, while other destinations keep
// it.
func TestCgroupForceInterceptPrefixesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup force-intercept prefixes")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, cgroupRoot, 102)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{
			Default: DecisionPass,
			DestinationCIDR: []CIDRDecision{
				{Prefix: netip.MustParsePrefix("198.18.0.0/15"), Action: DecisionIntercept, EchoReply: true},
				{Prefix: netip.MustParsePrefix("100.64.0.0/10"), Action: DecisionIntercept},
			},
		},
		Shared: ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		t.Fatal(err)
	}
	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer selfBypassMap.Close()
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableUDP:     true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer backend.Close()
	const listenerPort = 41020
	if err = backend.LoadPrograms(listenerPort); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program loading is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program attach is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	moveCurrentProcessToCgroup(t, path, cgroupRoot)

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, testCase := range []struct {
		destination string
		intercepted bool
	}{
		{"198.18.0.7:9", true},
		{"100.64.0.7:9", true},
		{"203.0.113.7:9", false},
	} {
		t.Run(testCase.destination, func(t *testing.T) {
			sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			// A passed datagram may have no route; only an intercepted one is
			// redirected to the loopback listener.
			_, _ = sender.WriteToUDPAddrPort([]byte(testCase.destination), netip.MustParseAddrPort(testCase.destination))
			if testCase.intercepted {
				assertUDPReceived(t, listener, testCase.destination)
			} else {
				assertUDPNotReceived(t, listener)
			}
		})
	}
}

// TestCgroupUDPFlowCacheRevalidatesRedirect covers a cached proxy decision
// whose redirect entry is gone, as after an LRU eviction, or now records
// another flow, as when that flow claimed the freed token. The cache must not
// send the datagram to a token userspace cannot map back to this destination.
func TestCgroupUDPFlowCacheRevalidatesRedirect(t *testing.T) {
	const listenerPort = 41010
	backend := startCgroupUDPIntegrationBackend(t, 101, listenerPort)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	cookie, err := udpSocketCookie(sender)
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddrPort("198.51.100.7:9")
	flowKey := udpFlowKey{SocketCookie: cookie, Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: destination.Port()}
	destination4 := destination.Addr().As4()
	copy(flowKey.Addr[:4], destination4[:])
	flows := backend.runtime.maps["cgroup_udp_flow"]
	redirects := backend.runtime.maps["cgroup_udp_redirect"]

	// send returns the token the flow cache holds after one datagram, and
	// requires the redirect entry for it to record this socket's destination.
	send := func(payload string) listenerLookupKey {
		t.Helper()
		if _, err := sender.WriteToUDPAddrPort([]byte(payload), destination); err != nil {
			t.Fatal(err)
		}
		assertUDPReceived(t, listener, payload)
		var flow udpFlowValue
		if err := flows.Lookup(&flowKey, &flow); err != nil {
			t.Fatalf("look up the UDP flow cache after %q: %v", payload, err)
		}
		if flow.Action != udpFlowActionProxy {
			t.Fatalf("UDP flow action after %q = %d, want proxy", payload, flow.Action)
		}
		var original originalDestinationValue
		if err := redirects.Lookup(&flow.Listener, &original); err != nil {
			t.Fatalf("after %q the UDP flow cache names token %v without a redirect entry: %v",
				payload, flow.Listener.TokenAddr[:4], err)
		}
		if original.SocketCookie != cookie || original.Port != destination.Port() ||
			[4]byte(original.Addr[:4]) != destination4 {
			t.Fatalf("after %q the UDP flow cache names a token recording %+v, want this socket's destination",
				payload, original)
		}
		return flow.Listener
	}

	token := send("first")
	if err = redirects.Delete(&token); err != nil {
		t.Fatal(err)
	}
	token = send("after eviction")

	claimed := originalDestinationValue{
		Family:       addressFamilyIPv4,
		Protocol:     ProtocolUDP,
		Port:         53,
		SocketCookie: cookie + 1,
	}
	copy(claimed.Addr[:4], netip.MustParseAddr("192.0.2.53").AsSlice())
	if err = redirects.Update(&token, &claimed, CiliumEBPF.UpdateExist); err != nil {
		t.Fatal(err)
	}
	if replacement := send("after reuse"); replacement == token {
		t.Fatal("the UDP flow cache kept a token another flow claimed")
	}
	var current originalDestinationValue
	if err = redirects.Lookup(&token, &current); err != nil || current != claimed {
		t.Fatalf("the other flow's redirect entry = %+v, %v; want it left alone", current, err)
	}
}

// TestCgroupUDPReleaseNotificationDropsCountOnlyLostEvents requires the drop
// counter to mean what UDPReleaseNotificationDrops documents: an event the
// full ring could not take. Unconnected sockets have no token to report.
func TestCgroupUDPReleaseNotificationDropsCountOnlyLostEvents(t *testing.T) {
	const listenerPort = 41011
	backend := startCgroupUDPIntegrationBackend(t, 102, listenerPort)
	if backend.UDPUserspaceCleanupMode() != cgroupUDPUserspaceCleanupRingBuffer {
		t.Skip("socket-release notification is unavailable")
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 8), Port: 9}

	unconnected, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unconnected.WriteToUDP([]byte("unconnected"), destination); err != nil {
		t.Fatal(err)
	}
	assertUDPReceived(t, listener, "unconnected")
	if err = unconnected.Close(); err != nil {
		t.Fatal(err)
	}

	connected, err := net.DialUDP("udp4", nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := udpSocketCookie(connected)
	if err != nil {
		t.Fatal(err)
	}
	if err = connected.Close(); err != nil {
		t.Fatal(err)
	}
	events := make(chan UDPReleaseEvent, 1)
	readErrors := make(chan error, 1)
	go func() {
		event, readErr := backend.ReadUDPRelease()
		if readErr != nil {
			readErrors <- readErr
			return
		}
		events <- event
	}()
	select {
	case event := <-events:
		if event.SocketCookie != cookie {
			t.Fatalf("UDP release event for socket %d, want the connected socket %d", event.SocketCookie, cookie)
		}
	case readErr := <-readErrors:
		t.Fatal(readErr)
	case <-time.After(5 * time.Second):
		t.Fatal("no UDP release event for the connected socket")
	}
	drops, err := backend.UDPReleaseNotificationDrops()
	if err != nil {
		t.Fatal(err)
	}
	if drops != 0 {
		t.Fatalf("UDP release notification drops = %d with an empty ring, want 0", drops)
	}
}

// startCgroupUDPIntegrationBackend attaches an IPv4 UDP backend that
// intercepts every destination to a dedicated cgroup and moves this process
// into it.
func startCgroupUDPIntegrationBackend(t *testing.T, index int, listenerPort uint16) *CgroupBackend {
	t.Helper()
	requireEBPFIntegration(t, "attach cgroup UDP interception")
	cgroupRoot, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, cgroupRoot, index)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	backend, err := prepareCgroupIntegrationBackend(path, false, true, false)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(listenerPort); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program loading is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup program attach is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	moveCurrentProcessToCgroup(t, path, cgroupRoot)
	return backend
}

func moveCurrentProcessToCgroup(t *testing.T, path, root string) {
	t.Helper()
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), pid, 0o644); err != nil {
		t.Skipf("cannot move integration process into cgroup: %v", err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(root, "cgroup.procs"), pid, 0o644)
	})
}

func udpSocketCookie(conn *net.UDPConn) (uint64, error) {
	var cookie uint64
	var controlErr error
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = rawConn.Control(func(fd uintptr) {
		cookie, controlErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	})
	if err != nil {
		return 0, err
	}
	return cookie, controlErr
}

func assertUDPReceived(t *testing.T, conn *net.UDPConn, want string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != want {
		t.Fatalf("received %q, want %q", buffer[:n], want)
	}
}

func assertUDPNotReceived(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 64)
	if n, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatalf("unexpected redirected packet %q", buffer[:n])
	} else if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, unix.EAGAIN) {
		// The net package may wrap EAGAIN as a timeout error; accept only those
		// two forms so real socket failures remain visible.
		t.Fatalf("unexpected token socket read error: %v", err)
	}
}

func createIntegrationCgroup(t *testing.T, root string, index int) (string, bool) {
	t.Helper()
	path := filepath.Join(root, fmt.Sprintf("sing-ebpf-test-%d-%d", os.Getpid(), index))
	if err := os.Mkdir(path, 0o755); err != nil {
		return root, false
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path, true
}

// assertCgroupUDPReleaseObserverLoaded catches a release-notification program
// that the verifier rejects: the loader then falls back to deadline cleanup
// without returning an error.
func assertCgroupUDPReleaseObserverLoaded(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	if !backend.runtime.socket_release_supported || features.HaveMapType(CiliumEBPF.RingBuf) != nil {
		return
	}
	if mode := backend.UDPUserspaceCleanupMode(); mode != cgroupUDPUserspaceCleanupRingBuffer {
		t.Fatalf("UDP userspace cleanup mode = %q, want %q: the socket-release notification program did not load",
			mode, cgroupUDPUserspaceCleanupRingBuffer)
	}
}

func prepareCgroupIntegrationBackend(path string, enableTCP, enableUDP, enableIPv6 bool) (*CgroupBackend, error) {
	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		return nil, err
	}
	policy, err := CompileActionPolicy(ActionPolicy{
		Local:  ActionScope{Default: DecisionIntercept},
		Shared: ActionScope{Default: DecisionIntercept},
	})
	if err != nil {
		_ = selfBypassMap.Close()
		return nil, err
	}
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableTCP:     enableTCP,
		EnableUDP:     enableUDP,
		EnableIPv6:    enableIPv6,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6:  netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	_ = selfBypassMap.Close()
	return backend, err
}

func assertCgroupProgramSet(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	for slot := range cgroupProgramDefinitions {
		loaded := backend.runtime.programs[slot] != nil
		if loaded != backend.cgroupProgramEnabled(slot) {
			t.Fatalf("program slot %d loaded=%v, enabled=%v, section=%s", slot, loaded, backend.cgroupProgramEnabled(slot), backend.cgroupProgramSection(slot))
		}
	}
	if backend.listenerPort == 0 {
		t.Fatal("cgroup listener port was not published to runtime")
	}
}

func assertCgroupMapABI(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	info, err := backend.runtime.maps["cgroup_socket_bypass"].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.KeySize != 8 || info.ValueSize != 4 {
		t.Fatalf("unexpected cgroup self-bypass map ABI: key=%d value=%d", info.KeySize, info.ValueSize)
	}
}

func assertCgroupUDPMapHandoff(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	original := netip.MustParseAddrPort("192.0.2.10:5353")
	token, err := backend.ReserveUDPReplyRedirect(original, backend.listenerPort)
	if err != nil {
		t.Fatal(err)
	}
	listener := netip.AddrPortFrom(token, backend.listenerPort)
	controlKey := uint32(0)
	var controlBefore cgroupControl
	if err = backend.runtime.maps["cgroup_control"].Lookup(&controlKey, &controlBefore); err != nil {
		t.Fatal(err)
	}
	if err = backend.ResetNetworkState(); err != nil {
		t.Fatal(err)
	}
	var controlAfter cgroupControl
	if err = backend.runtime.maps["cgroup_control"].Lookup(&controlKey, &controlAfter); err != nil {
		t.Fatal(err)
	}
	if controlAfter.NetworkGeneration != controlBefore.NetworkGeneration+1 {
		t.Fatalf(
			"network generation did not advance: before=%d after=%d",
			controlBefore.NetworkGeneration,
			controlAfter.NetworkGeneration,
		)
	}
	recovered, err := backend.LookupOriginal(ProtocolUDP, listener)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Destination != original {
		t.Fatalf("unexpected UDP original destination: got %s want %s", recovered.Destination, original)
	}
	if _, err = backend.TakeOriginal(ProtocolUDP, listener); err != nil {
		t.Fatal(err)
	}
	assertCgroupHandoffCleanup(t, backend, ProtocolUDP, listener)
}

func assertCgroupTCPMapHandoff(t *testing.T, backend *CgroupBackend) {
	t.Helper()
	listener := netip.MustParseAddrPort("127.128.0.1:" + fmt.Sprint(backend.listenerPort))
	key, err := makeListenerLookupKey(ProtocolTCP, listener)
	if err != nil {
		t.Fatal(err)
	}
	original := originalDestinationValue{
		Family:       addressFamilyIPv4,
		Protocol:     ProtocolTCP,
		Port:         443,
		SocketCookie: 101,
	}
	originalAddress := netip.MustParseAddr("192.0.2.20").As4()
	copy(original.Addr[:4], originalAddress[:])
	if err = updateMap(backend.tcpRedirectMapFD, unsafe.Pointer(&key), unsafe.Pointer(&original)); err != nil {
		t.Fatal(err)
	}
	recovered, err := backend.TakeOriginal(ProtocolTCP, listener)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Destination != netip.MustParseAddrPort("192.0.2.20:443") {
		t.Fatalf("unexpected TCP original destination: got %s", recovered.Destination)
	}
	assertCgroupHandoffCleanup(t, backend, ProtocolTCP, listener)
}

func assertCgroupHandoffCleanup(t *testing.T, backend *CgroupBackend, protocol uint8, listener netip.AddrPort) {
	t.Helper()
	_, err := backend.LookupOriginal(protocol, listener)
	if backend.lookupAndDeleteMode.Load() == mapLookupAndDeleteUnsupported {
		// The documented fallback retains the bounded entry. A separate
		// lookup/delete would race a kernel replacement of the same key.
		if err != nil {
			t.Fatalf("non-atomic handoff did not retain its record: %v", err)
		}
		if err = backend.DeleteRedirect(protocol, listener); err != nil {
			t.Fatal(err)
		}
		_, err = backend.LookupOriginal(protocol, listener)
	}
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("redirect remained after atomic take or explicit cleanup: %v", err)
	}
}

func cgroupIntegrationUnavailable(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOMEM) || errors.Is(err, linuxErrnoNotSupported)
}
