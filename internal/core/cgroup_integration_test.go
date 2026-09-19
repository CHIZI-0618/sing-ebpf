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
			}
		})
	}
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
	policy, err := CompilePolicy(PolicyConfig{
		EnableUDP: true,
		Local: LocalPolicy{
			DNSMode:              DNSModeRespectPolicy,
			IncludeUIDConfigured: true,
			IncludeUID:           []UIDRange{{Start: uid, End: uid}},
		},
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
		MapCapacity:   CgroupMapCapacity{UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
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
	token, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 128, 0, 1), Port: listenerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	targetAddr := target.LocalAddr().(*net.UDPAddr)

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
	flowKey := udpFlowKey{SocketCookie: cookie, Family: addressFamilyIPv4, Protocol: ProtocolUDP, Port: uint16(targetAddr.Port)}
	copy(flowKey.Addr[:4], targetAddr.IP.To4())
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
	if _, err = cached.WriteToUDP([]byte("cached"), targetAddr); err != nil {
		t.Fatal(err)
	}
	assertUDPReceived(t, target, "cached")
	assertUDPNotReceived(t, token)
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
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: enableTCP, EnableUDP: enableUDP})
	if err != nil {
		_ = selfBypassMap.Close()
		return nil, err
	}
	policy.local.EnableBypassCIDR = true
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
	if _, err = backend.LookupOriginal(ProtocolUDP, listener); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("UDP redirect remained after take: %v", err)
	}
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
	if _, err = backend.LookupOriginal(ProtocolTCP, listener); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("TCP redirect remained after take: %v", err)
	}
}

func cgroupIntegrationUnavailable(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOMEM) || errors.Is(err, linuxErrnoNotSupported)
}
