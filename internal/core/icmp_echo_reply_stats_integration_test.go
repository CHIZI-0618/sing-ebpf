//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"net/netip"
	"testing"
)

// TestICMPEchoReplyStatsCountsPassThroughNotOrdinaryTraffic distinguishes an
// unsupported echo request from unrelated traffic to the same ForceIntercept.
func TestICMPEchoReplyStatsCountsPassThroughNotOrdinaryTraffic(t *testing.T) {
	requireEBPFIntegration(t, "verify icmp_echo_reply_stats counts pass-through correctly")
	policy := newTestForceInterceptPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:  65530,
		EnableLocal:   true,
		EnableIPv4:    true,
		EnableTCP:     true,
		Policy:        policy,
		ICMPEchoReply: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	program := backend.ICMPEchoLocalReplyProgram(TCLinkFramingEthernet)
	if program == nil {
		t.Fatal("icmp_echo_reply local Ethernet program is unavailable")
	}

	before, err := backend.ICMPEchoPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount before: %v", err)
	}

	// An ICMP Echo Request with IPv4 options: this object commits to no
	// options at all, so this is a disqualified ICMP packet -- PassThrough.
	validIPv4 := testIPv4EchoPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"))
	ipv4Options := append(validIPv4, 0, 0, 0, 0)
	copy(ipv4Options[14+24:], validIPv4[14+20:])
	ipv4Options[14] = 0x46
	action, _ := runTCProgram(t, program, ipv4Options)
	if action != testTCActUnspec {
		t.Fatalf("disqualified ICMP packet was claimed: action=%d", action)
	}

	afterDisqualifiedICMP, err := backend.ICMPEchoPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount after disqualified ICMP: %v", err)
	}
	if afterDisqualifiedICMP != before+1 {
		t.Fatalf("PassThroughCount = %d, want %d after one disqualified ICMP packet", afterDisqualifiedICMP, before+1)
	}

	// An ordinary TCP packet to the same ForceIntercept destination: not ICMP at
	// all, so this must not move PassThroughCount even one more.
	tcpPacket := testIPv4TCPPacket(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.0.1"), 51234, 80)
	action, _ = runTCProgram(t, program, tcpPacket)
	if action != testTCActUnspec {
		t.Fatalf("ordinary TCP packet was claimed: action=%d", action)
	}

	afterTCP, err := backend.ICMPEchoPassThroughCount()
	if err != nil {
		t.Fatalf("read PassThroughCount after TCP packet: %v", err)
	}
	if afterTCP != afterDisqualifiedICMP {
		t.Fatalf("PassThroughCount = %d, want unchanged at %d -- an ordinary TCP packet must not count as an ICMP pass-through",
			afterTCP, afterDisqualifiedICMP)
	}
}

// TestICMPEchoReplyStatsZeroWhenDisabled confirms the trivial case: a backend
// that never enabled icmp_echo_reply has no counters to read at all, matching
// ICMPEchoReplyEnabled's own existing false-when-off contract.
func TestICMPEchoReplyStatsZeroWhenDisabled(t *testing.T) {
	policy := newTestForceInterceptPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65530,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if _, err := backend.ICMPEchoReplyCount(); err == nil {
		t.Fatal("ICMPEchoReplyCount succeeded on a backend that never enabled icmp_echo_reply")
	}
	if _, err := backend.ICMPEchoPassThroughCount(); err == nil {
		t.Fatal("ICMPEchoPassThroughCount succeeded on a backend that never enabled icmp_echo_reply")
	}
	if _, err := backend.ICMPEchoRewriteFailureCount(); err == nil {
		t.Fatal("ICMPEchoRewriteFailureCount succeeded on a backend that never enabled icmp_echo_reply")
	}
}
