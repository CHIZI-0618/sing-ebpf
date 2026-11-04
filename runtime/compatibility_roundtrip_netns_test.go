//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	core "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func compatibilityNamespace(t *testing.T) {
	t.Helper()
	enterTestNetworkNamespace(t)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

func TestCompatibilityCgroupTCPRoundTrip(t *testing.T) {
	testCompatibilityCgroupRoundTrip(t, false)
}

func TestCompatibilityCgroupUDPRoundTrip(t *testing.T) {
	testCompatibilityCgroupRoundTrip(t, true)
}

func testCompatibilityCgroupRoundTrip(t *testing.T, udp bool) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			compatibilityNamespace(t)
			original, err := core.DetectProcessCgroup2Path()
			if err != nil {
				t.Fatal(err)
			}
			group, err := os.MkdirTemp(original, "sb-compat-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(group)
			prefix := netip.MustParsePrefix("127.128.0.0/9")
			network, destination := "tcp4", "203.0.113.10:8443"
			if v6 {
				prefix = netip.MustParsePrefix("fd00:1234::/64")
				network, destination = "tcp6", "[2001:db8:2::10]:8443"
			}
			routes, err := core.NewLocalRouteSet([]netip.Prefix{prefix})
			if err != nil {
				t.Fatal(err)
			}
			defer routes.Close()
			listener, err := net.Listen(network, ":0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var packet *net.UDPConn
			if udp {
				listen := isolatedTestListenConfig(v6)
				connection, err := listen.ListenPacket(context.Background(), "udp"+network[3:], fmt.Sprintf(":%d", listener.Addr().(*net.TCPAddr).Port))
				if err != nil {
					t.Fatal(err)
				}
				packet = connection.(*net.UDPConn)
				defer packet.Close()
				if v6 {
					err = ipv6.NewPacketConn(packet).SetControlMessage(ipv6.FlagDst, true)
				} else {
					err = ipv4.NewPacketConn(packet).SetControlMessage(ipv4.FlagDst, true)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			policy, err := core.CompileActionPolicy(core.ActionPolicy{Local: core.ActionScope{Default: core.DecisionIntercept}})
			if err != nil {
				t.Fatal(err)
			}
			bypass, err := core.NewSelfBypassWithCapacity(16)
			if err != nil {
				t.Fatal(err)
			}
			defer bypass.Close()
			config := core.CgroupConfig{Path: group, EnableTCP: !udp, EnableUDP: udp, EnableIPv6: v6, Policy: policy, SelfBypass: bypass,
				MapCapacity: core.CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 16}, UDPTimeout: time.Minute}
			if v6 {
				config.RedirectIPv6 = prefix
			} else {
				config.RedirectIPv4 = prefix
			}
			backend, err := core.PrepareCgroup(config)
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			if err = backend.LoadPrograms(uint16(listener.Addr().(*net.TCPAddr).Port)); err != nil {
				t.Fatal(err)
			}
			if err = backend.Attach(); err != nil {
				t.Fatal(err)
			}
			pid := []byte(strconv.Itoa(os.Getpid()))
			if err = os.WriteFile(filepath.Join(group, "cgroup.procs"), pid, 0644); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(filepath.Join(original, "cgroup.procs"), pid, 0644); err != nil {
					t.Error(err)
				}
			}()
			if udp {
				for _, connected := range []bool{false, true} {
					t.Logf("connected=%v", connected)
					// Stay on the OS thread that owns the test network namespace.
					testCompatibilityCgroupUDPExchange(t, backend, packet, v6, connected, destination)
				}
				return
			}
			client, err := net.DialTimeout(network, destination, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// net fills RemoteAddr from getpeername after connect.
			if peer := client.RemoteAddr().(*net.TCPAddr).AddrPort(); peer != netip.MustParseAddrPort(destination) {
				t.Fatalf("getpeername reported %s, want %s", peer, destination)
			}
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			originalDestination, err := backend.TakeOriginal(core.ProtocolTCP, server.LocalAddr().(*net.TCPAddr).AddrPort())
			if err != nil {
				t.Fatal(err)
			}
			if originalDestination.Destination != netip.MustParseAddrPort(destination) {
				t.Fatalf("wrong original destination: %+v", originalDestination)
			}
			assertCompatibilityTCPExchange(t, client, server)
			if err = backend.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testCompatibilityCgroupUDPExchange(t *testing.T, backend *core.CgroupBackend, server *net.UDPConn, v6, connected bool, destination string) {
	t.Helper()
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(destination))
	var client *net.UDPConn
	var err error
	if connected {
		client, err = net.DialUDP(network, nil, remote)
	} else {
		client, err = net.ListenUDP(network, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if connected {
		// net fills RemoteAddr from getpeername after connect.
		if peer := client.RemoteAddr().(*net.UDPAddr).AddrPort(); peer != remote.AddrPort() {
			t.Fatalf("getpeername reported %s, want %s", peer, remote.AddrPort())
		}
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("cgroup UDP compatibility")
	if connected {
		_, err = client.Write(payload)
	} else {
		_, err = client.WriteToUDP(payload, remote)
	}
	if err != nil {
		t.Fatal(err)
	}
	buffer, control := make([]byte, 128), make([]byte, 128)
	n, controlN, _, source, err := server.ReadMsgUDP(buffer, control)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatal("UDP request mismatch")
	}
	var token net.IP
	var replyControl []byte
	if v6 {
		var message ipv6.ControlMessage
		err = message.Parse(control[:controlN])
		token = message.Dst
		replyControl = (&ipv6.ControlMessage{Src: token}).Marshal()
	} else {
		var message ipv4.ControlMessage
		err = message.Parse(control[:controlN])
		token = message.Dst
		replyControl = (&ipv4.ControlMessage{Src: token}).Marshal()
	}
	if err != nil {
		t.Fatal(err)
	}
	address, ok := netip.AddrFromSlice(token)
	if !ok {
		t.Fatal("missing UDP token destination")
	}
	original, err := backend.LookupOriginal(core.ProtocolUDP, netip.AddrPortFrom(address.Unmap(), uint16(server.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	if original.Destination != remote.AddrPort() {
		t.Fatalf("wrong UDP original destination: %+v", original)
	}
	if _, _, err = server.WriteMsgUDP(buffer[:n], replyControl, source); err != nil {
		t.Fatal(err)
	}
	n, from, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) || from.AddrPort() != remote.AddrPort() {
		t.Fatalf("UDP reply mismatch: payload=%q source=%v", buffer[:n], from)
	}
}

func assertCompatibilityTCPExchange(t *testing.T, client, server net.Conn) {
	t.Helper()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	for _, endpoints := range [][2]net.Conn{{client, server}, {server, client}} {
		if _, err := endpoints[0].Write([]byte("compatibility")); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len("compatibility"))
		if _, err := io.ReadFull(endpoints[1], buffer); err != nil {
			t.Fatal(err)
		}
		if string(buffer) != "compatibility" {
			t.Fatal("TCP payload mismatch")
		}
	}
}

func TestSharedRewriteRoundTripIntegration(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) { testSharedRewriteRoundTrip(t, v6) })
	}
}

func testSharedRewriteRoundTrip(t *testing.T, v6 bool) {
	compatibilityNamespace(t)
	host, peer := createTestVethPair(t, "sbcompat0", "sbcompat1")
	clientNS, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer clientNS.Close()
	if err = netlink.LinkSetNsFd(peer, int(clientNS.handle)); err != nil {
		t.Fatal(err)
	}
	if err = clientNS.with(func() error {
		var err error
		peer, err = netlink.LinkByName("sbcompat1")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(peer)
	}); err != nil {
		t.Fatal(err)
	}
	family, suffix, hostAddress, clientAddress, remote := unix.AF_INET, "4", "192.0.2.1/24", "192.0.2.2/24", "203.0.113.10"
	prefix := netip.MustParsePrefix("127.128.0.0/9")
	if v6 {
		family, suffix, hostAddress, clientAddress, remote = unix.AF_INET6, "6", "fd00:1::1/64", "fd00:1::2/64", "2001:db8:2::10"
		prefix = netip.MustParsePrefix("fd00:1234::/64")
	}
	addAddress := func(link netlink.Link, value string) error {
		addr, err := netlink.ParseAddr(value)
		if err != nil {
			return err
		}
		addr.Flags = unix.IFA_F_NODAD
		return netlink.AddrAdd(link, addr)
	}
	if err = addAddress(host, hostAddress); err != nil {
		t.Fatal(err)
	}
	// Keep neighbor discovery independent of the synthetic token reply source.
	clientIP := netip.MustParsePrefix(clientAddress).Addr()
	if err = netlink.NeighSet(&netlink.Neigh{LinkIndex: host.Attrs().Index, Family: family, IP: net.IP(clientIP.AsSlice()), HardwareAddr: peer.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT}); err != nil {
		t.Fatal(err)
	}
	if err = clientNS.with(func() error {
		if err := addAddress(peer, clientAddress); err != nil {
			return err
		}
		addr := netip.MustParseAddr(remote)
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: peer.Attrs().Index, Family: family, Dst: &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}, Scope: netlink.SCOPE_LINK}); err != nil {
			return err
		}
		return netlink.NeighSet(&netlink.Neigh{LinkIndex: peer.Attrs().Index, Family: family, IP: net.ParseIP(remote), HardwareAddr: host.Attrs().HardwareAddr, State: netlink.NUD_PERMANENT})
	}); err != nil {
		t.Fatal(err)
	}
	// RPF is fixture policy; the runtime itself must only own route_localnet.
	for _, device := range []string{"all", host.Attrs().Name} {
		if err = os.WriteFile("/proc/sys/net/ipv4/conf/"+device+"/rp_filter", []byte("0"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	routes, err := core.NewLocalRouteSet([]netip.Prefix{prefix})
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()
	listen := isolatedTestListenConfig(v6)
	tcp, err := listen.Listen(context.Background(), "tcp"+suffix, ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	transparentControl := listen.Control
	listen.Control = func(network, address string, raw syscall.RawConn) error {
		if err := transparentControl(network, address, raw); err != nil {
			return err
		}
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			if v6 {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVPKTINFO, 1)
			} else {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_PKTINFO, 1)
			}
		})
		if err != nil {
			return err
		}
		return optionErr
	}
	packet, err := listen.ListenPacket(context.Background(), "udp"+suffix, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	udp := packet.(*net.UDPConn)
	policy, err := core.CompileActionPolicy(core.ActionPolicy{Shared: core.ActionScope{Default: core.DecisionIntercept}})
	if err != nil {
		t.Fatal(err)
	}
	config := core.SharedPacketRewriteConfig{ListenerPort: uint16(port), EnableTCP: true, EnableUDP: true, Policy: policy, MapCapacity: core.SharedPacketRewriteMapCapacity{Proxy: 64, Bypass: 64}, UDPTimeout: time.Minute}
	if v6 {
		config.RedirectIPv6 = prefix
	} else {
		config.RedirectIPv4 = prefix
	}
	owner := NewSharedPacketRewriteRuntime(SharedPacketRewriteRuntimeConfig{Priority: 2, Hooks: SharedPacketRewriteHooks{PrepareBackend: func() (*core.SharedPacketRewriteBackend, error) { return core.PrepareSharedPacketRewrite(config) }}})
	defer owner.Close()
	if err = owner.Reconcile([]string{host.Attrs().Name}, nil); err != nil {
		t.Fatal(err)
	}
	backend := owner.Backend()
	var client net.Conn
	if err = clientNS.with(func() error {
		var err error
		client, err = net.DialTimeout("tcp"+suffix, net.JoinHostPort(remote, "8443"), 3*time.Second)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = tcp.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	server, err := tcp.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	original, flow, err := backend.LookupFlow(core.ProtocolTCP, server.RemoteAddr().(*net.TCPAddr).AddrPort(), server.LocalAddr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.ReleaseFlow(flow)
	if original.Destination != netip.AddrPortFrom(netip.MustParseAddr(remote), 8443) {
		t.Fatal("TCP destination mismatch")
	}
	assertCompatibilityTCPExchange(t, client, server)
	var udpClient net.Conn
	if err = clientNS.with(func() error {
		var err error
		udpClient, err = net.DialTimeout("udp"+suffix, net.JoinHostPort(remote, "9681"), 3*time.Second)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(3 * time.Second))
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = udpClient.Write([]byte("UDP compatibility")); err != nil {
		t.Fatal(err)
	}
	buffer, control := make([]byte, 128), make([]byte, 128)
	n, controlN, _, source, err := udp.ReadMsgUDP(buffer, control)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "UDP compatibility" {
		t.Fatal("UDP request mismatch")
	}
	var token net.IP
	var replyControl []byte
	if v6 {
		var message ipv6.ControlMessage
		if err = message.Parse(control[:controlN]); err != nil {
			t.Fatal(err)
		}
		token = message.Dst
		replyControl = (&ipv6.ControlMessage{Src: token}).Marshal()
	} else {
		var message ipv4.ControlMessage
		if err = message.Parse(control[:controlN]); err != nil {
			t.Fatal(err)
		}
		token = message.Dst
		replyControl = (&ipv4.ControlMessage{Src: token}).Marshal()
	}
	tokenAddress, ok := netip.AddrFromSlice(token)
	if !ok {
		t.Fatal("missing UDP token destination")
	}
	original, udpFlow, err := backend.LookupFlow(core.ProtocolUDP, source.AddrPort(), netip.AddrPortFrom(tokenAddress.Unmap(), uint16(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.ReleaseFlow(udpFlow)
	if original.Destination != netip.AddrPortFrom(netip.MustParseAddr(remote), 9681) {
		t.Fatal("UDP destination mismatch")
	}
	if _, _, err = udp.WriteMsgUDP(buffer[:n], replyControl, source); err != nil {
		t.Fatal(err)
	}
	n, err = udpClient.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "UDP compatibility" {
		t.Fatal("UDP reply mismatch")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	if !owner.IsClosed() {
		t.Fatal("runtime retained resources after successful close")
	}
}
