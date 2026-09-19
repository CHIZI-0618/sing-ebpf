//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestTCProgramRunIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run unified TC eBPF programs in the kernel")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:           true,
		SharedDNSMode:       DNSModeRespectPolicy,
		SharedBypassPrivate: true,
		ForceInterceptIPv4:  netip.MustParsePrefix("198.18.0.0/15"),
		IncludeSourceMAC:    []MACAddress{{0x02, 0, 0, 0, 0, 1}},
		IncludeSourceCIDR:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		ExcludeSourceCIDR:   []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65531,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	selected := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53000, 443,
	)
	action, _ := runTCProgram(t, sharedIngress, selected)
	if action != testTCActShot {
		t.Fatalf("selected flow did not reach socket assignment: action=%d", action)
	}

	matchedCIDR := append([]byte(nil), selected...)
	matchedCIDR[11] = 2
	action, _ = runTCProgram(t, sharedIngress, matchedCIDR)
	if action != testTCActShot {
		t.Fatalf("source CIDR match did not select a client without the included MAC: action=%d", action)
	}

	unselectedClient := testIPv4TCPPacket(
		netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("203.0.113.10"), 53001, 443,
	)
	// testIPv4TCPPacket uses the included MAC by default. Change it here so
	// this case really exercises a client matching neither source selector.
	unselectedClient[11] = 2
	action, _ = runTCProgram(t, sharedIngress, unselectedClient)
	if action != testTCActUnspec {
		t.Fatalf("client matching neither source selector was intercepted: action=%d", action)
	}

	excludedCIDR := testIPv4TCPPacket(
		netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.20"), 53002, 443,
	)
	action, _ = runTCProgram(t, sharedIngress, excludedCIDR)
	if action != testTCActUnspec {
		t.Fatalf("excluded source CIDR was intercepted despite matching the included MAC: action=%d", action)
	}

	private := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.168.1.1"), 53003, 443,
	)
	action, _ = runTCProgram(t, sharedIngress, private)
	if action != testTCActUnspec {
		t.Fatalf("private destination was intercepted: action=%d", action)
	}

	forceIntercept := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53004, 443,
	)
	forceIntercept[11] = 2
	action, _ = runTCProgram(t, sharedIngress, forceIntercept)
	if action != testTCActShot {
		t.Fatalf("ForceIntercept did not override source and private bypass: action=%d", action)
	}

	bypassPolicy, err := CompileBypassCIDRPolicy([]netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = backend.UpdateCompiledBypassCIDR(bypassPolicy); err != nil {
		t.Fatal(err)
	}
	bypassedHTTPS := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("1.1.1.1"), 53005, 443,
	)
	action, _ = runTCProgram(t, sharedIngress, bypassedHTTPS)
	if action != testTCActUnspec {
		t.Fatalf("destination bypass policy did not bypass HTTPS: action=%d", action)
	}
	respectedDNS := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("1.1.1.1"), 53006, 53,
	)
	action, _ = runTCProgram(t, sharedIngress, respectedDNS)
	if action != testTCActShot {
		t.Fatalf("respect_policy DNS did not override destination bypass: action=%d", action)
	}

}

func TestForceInterceptPolicyPrecedenceIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify ForceIntercept policy precedence in every TC data plane")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:           true,
		Local:               LocalPolicy{DNSMode: DNSModeOff},
		SharedDNSMode:       DNSModeOff,
		SharedBypassPrivate: true,
		ForceInterceptIPv4:  netip.MustParsePrefix("198.18.0.0/15"),
		ForceInterceptIPv6:  netip.MustParsePrefix("fd00:198:18::/48"),
		IncludeSourceMAC:    []MACAddress{{0x02, 0, 0, 0, 0, 3}},
		LocalBypassPort:     []PortRange{{Start: 53, End: 53}},
		SharedBypassPort:    []PortRange{{Start: 53, End: 53}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bypass, err := CompileBypassCIDRPolicy([]netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fd00:198:18::/48"),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("socket_assign", func(t *testing.T) {
		backend, err := PrepareTC(TCConfig{
			ListenerPort:     65531,
			EnableShared:     true,
			EnableIPv4:       true,
			EnableSharedIPv6: true,
			EnableTCP:        true,
			Policy:           policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = backend.Close() })
		if _, err = backend.UpdateCompiledBypassCIDR(bypass); err != nil {
			t.Fatal(err)
		}
		if err = backend.Enable(); err != nil {
			t.Fatal(err)
		}
		program := backend.runtime.programs[tcProgramSharedIngressEthernet]
		for name, packet := range forceInterceptPolicyPrecedencePackets() {
			t.Run(name, func(t *testing.T) {
				action, _ := runTCProgram(t, program, packet)
				if action != testTCActShot {
					t.Fatalf("ForceIntercept did not override DNS, source, port, private, and CIDR bypass: action=%d", action)
				}
			})
		}
	})

	t.Run("packet_rewrite", func(t *testing.T) {
		backend, err := PrepareSharedPacketRewrite(nil, SharedPacketRewriteConfig{
			ListenerPort: 65531,
			EnableTCP:    true,
			RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
			RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
			Policy:       policy,
			MapCapacity:  DefaultSharedPacketRewriteMapCapacity(),
			UDPTimeout:   time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = backend.Close() })
		if _, err = backend.UpdateCompiledBypassCIDR(bypass); err != nil {
			t.Fatal(err)
		}
		if err = backend.Enable(); err != nil {
			t.Fatal(err)
		}
		program := backend.runtime.programs[sharedNetworkProgramIngress]
		for name, packet := range forceInterceptPolicyPrecedencePackets() {
			t.Run(name, func(t *testing.T) {
				_, output := runTCProgram(t, program, packet)
				if bytes.Equal(output, packet) {
					t.Fatal("ForceIntercept packet was not rewritten after matching lower-priority bypass policies")
				}
			})
		}
	})
}

func forceInterceptPolicyPrecedencePackets() map[string][]byte {
	return map[string][]byte{
		"IPv4": testIPv4TCPPacket(
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53000, 53,
		),
		"IPv6": testIPv6TCPPacket(
			netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fd00:198:18::1"), 53001, 53, nil,
		),
	}
}

func TestTCIPv6PathIsolationIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC eBPF IPv6 path isolation")
	packet := testIPv6TCPPacket(
		netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:4860:4860::8888"), 53000, 443, nil,
	)
	for _, testCase := range []struct {
		name       string
		config     TCConfig
		program    int
		wantAction uint32
	}{
		{
			// EnableShared is deliberately the only role enabled: with it
			// off, tcProgramSharedIngressEthernet is never loaded at all
			// (see prepareTC's config.EnableShared gate in tc.go), and
			// backend.runtime.programs[tcProgramSharedIngressEthernet]
			// stays nil -- indexing it below would still compile, but
			// runTCProgram's Program.Run on a nil *ebpf.Program panics
			// rather than failing the test with a clear message. This case
			// previously enabled Local instead of Shared by mistake, which
			// is exactly that nil-program panic; the fix is the config, not
			// runTCProgram or the loader.
			"shared IPv6 disabled on shared program",
			TCConfig{EnableShared: true, EnableIPv4: true, EnableTCP: true},
			tcProgramSharedIngressEthernet,
			testTCActUnspec,
		},
		{
			"shared enabled on shared program",
			TCConfig{EnableShared: true, EnableIPv4: true, EnableSharedIPv6: true, EnableTCP: true},
			tcProgramSharedIngressEthernet,
			testTCActShot,
		},
		{
			"local enabled on delivery program",
			TCConfig{EnableLocal: true, EnableIPv4: true, EnableLocalIPv6: true, EnableTCP: true},
			tcProgramDeliveryIngress,
			testTCActShot,
		},
		{
			// Same fix as the first case, mirrored: tcProgramDeliveryIngress
			// is only loaded when EnableLocal is set (it is part of the
			// local TC path's veth infrastructure), so this needs Local
			// enabled with its IPv6 specifically off, not Shared.
			"local IPv6 disabled on delivery program",
			TCConfig{EnableLocal: true, EnableIPv4: true, EnableTCP: true},
			tcProgramDeliveryIngress,
			testTCActUnspec,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.config.ListenerPort = 65531
			backend, err := PrepareTC(testCase.config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			if err = backend.Enable(); err != nil {
				t.Fatal(err)
			}
			action, _ := runTCProgram(t, backend.runtime.programs[testCase.program], packet)
			if action != testCase.wantAction {
				t.Fatalf("unexpected action: %d != %d", action, testCase.wantAction)
			}
		})
	}
}

func TestTCFragmentPolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC eBPF fragment policy")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:     65531,
		EnableShared:     true,
		EnableIPv4:       true,
		EnableSharedIPv6: true,
		EnableTCP:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	ipv4First := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53000, 443,
	)
	binary.BigEndian.PutUint16(ipv4First[20:22], 0x2000)
	ipv4Later := append([]byte(nil), ipv4First...)
	binary.BigEndian.PutUint16(ipv4Later[20:22], 1)
	for name, packet := range map[string][]byte{
		"IPv4 first fragment": ipv4First,
		"IPv4 later fragment": ipv4Later,
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := runTCProgram(t, sharedIngress, packet)
			if action != testTCActUnspec {
				t.Fatalf("fragment was intercepted: action=%d", action)
			}
		})
	}

	moreFragments := uint16(1)
	laterFragment := uint16(8)
	atomicFragment := uint16(0)
	for _, testCase := range []struct {
		name       string
		fragment   *uint16
		wantAction uint32
	}{
		{"IPv6 first fragment", &moreFragments, testTCActUnspec},
		{"IPv6 later fragment", &laterFragment, testTCActUnspec},
		{"IPv6 atomic fragment", &atomicFragment, testTCActShot},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			packet := testIPv6TCPPacket(
				netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:4860:4860::8888"),
				53000, 443, testCase.fragment,
			)
			action, _ := runTCProgram(t, sharedIngress, packet)
			if action != testCase.wantAction {
				t.Fatalf("unexpected action: %d != %d", action, testCase.wantAction)
			}
		})
	}
}

func TestSharedPacketRewriteFragmentPolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify shared packet-rewrite fragment policy")
	backend, err := PrepareSharedPacketRewrite(nil, SharedPacketRewriteConfig{
		ListenerPort: 65531,
		EnableTCP:    true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		Policy:       newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15"),
		MapCapacity:  DefaultSharedPacketRewriteMapCapacity(),
		UDPTimeout:   time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}

	ingress := backend.runtime.programs[sharedNetworkProgramIngress]
	egress := backend.runtime.programs[sharedNetworkProgramEgress]
	ipv4Ingress := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53000, 443,
	)
	binary.BigEndian.PutUint16(ipv4Ingress[20:22], 0x2000)
	ipv4Egress := testIPv4TCPPacket(
		netip.MustParseAddr("127.128.0.1"), netip.MustParseAddr("192.0.2.10"), 65531, 53000,
	)
	binary.BigEndian.PutUint16(ipv4Egress[20:22], 0x2000)
	moreFragments := uint16(1)
	ipv6Ingress := testIPv6TCPPacket(
		netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fd00:198:18::1"), 53000, 443, &moreFragments,
	)
	ipv6Egress := testIPv6TCPPacket(
		netip.MustParseAddr("fd53:696e:672d:626f::1"), netip.MustParseAddr("2001:db8::10"), 65531, 53000, &moreFragments,
	)
	for _, testCase := range []struct {
		name    string
		program *CiliumEBPF.Program
		packet  []byte
	}{
		{"IPv4 ingress fragment", ingress, ipv4Ingress},
		{"IPv4 egress fragment", egress, ipv4Egress},
		{"IPv6 ingress fragment", ingress, ipv6Ingress},
		{"IPv6 egress fragment", egress, ipv6Egress},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			action, _ := runTCProgram(t, testCase.program, testCase.packet)
			if action != testTCActUnspec {
				t.Fatalf("fragment was not passed symmetrically: action=%d", action)
			}
		})
	}

	if passes, err := backend.IngressFragmentPasses(); err != nil {
		t.Fatal(err)
	} else if passes != 2 {
		t.Fatalf("ingress fragment passes = %d, want 2", passes)
	}
	if passes, err := backend.EgressFragmentPasses(); err != nil {
		t.Fatal(err)
	} else if passes != 2 {
		t.Fatalf("egress fragment passes = %d, want 2", passes)
	}
}
