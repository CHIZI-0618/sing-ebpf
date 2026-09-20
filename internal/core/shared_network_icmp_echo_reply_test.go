//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
	"time"
)

// newTestSharedNetworkForceInterceptPolicy compiles a CompiledPolicy carrying only
// what PrepareSharedPacketRewrite's icmp_echo_reply wiring needs.
func newTestSharedNetworkForceInterceptPolicy(t *testing.T, forceInterceptIPv4 string) CompiledPolicy {
	t.Helper()
	config := ActionPolicy{
		EnableTCP: true,
		Local:     ActionScope{Default: DecisionIntercept},
		Shared:    ActionScope{Default: DecisionIntercept},
	}
	if forceInterceptIPv4 != "" {
		config.Shared.DestinationCIDR = []CIDRDecision{{Prefix: netip.MustParsePrefix(forceInterceptIPv4), Action: DecisionIntercept}}
	}
	policy, err := CompileActionPolicy(config)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return policy
}

func newTestSharedPacketRewriteConfig(policy CompiledPolicy, icmpEchoReply bool) SharedPacketRewriteConfig {
	return SharedPacketRewriteConfig{
		ListenerPort:  34567,
		EnableTCP:     true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		Policy:        policy,
		MapCapacity:   DefaultSharedPacketRewriteMapCapacity(),
		UDPTimeout:    5 * time.Minute,
		ICMPEchoReply: icmpEchoReply,
	}
}

// TestPrepareSharedPacketRewriteLoadsICMPEchoReplyWhenRequested covers the standalone
// ForceIntercept responder used by packet-rewrite.
func TestPrepareSharedPacketRewriteLoadsICMPEchoReplyWhenRequested(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, true))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if !backend.ICMPEchoReplyEnabled() {
		t.Fatal("ICMPEchoReplyEnabled() = false after requesting icmp_echo_reply=reply")
	}
	if fd := backend.ICMPEchoSharedReplyProgramFD(TCLinkFramingEthernet); fd < 0 {
		t.Fatal("shared reply program FD is unset")
	}
}

// TestPrepareSharedPacketRewriteWithoutICMPEchoReplyLoadsNothingExtra confirms the
// default, feature-off path costs nothing beyond the config check.
func TestPrepareSharedPacketRewriteWithoutICMPEchoReplyLoadsNothingExtra(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if backend.ICMPEchoReplyEnabled() {
		t.Fatal("ICMPEchoReplyEnabled() = true without requesting icmp_echo_reply=reply")
	}
	if fd := backend.ICMPEchoSharedReplyProgramFD(TCLinkFramingEthernet); fd >= 0 {
		t.Fatalf("shared reply program FD = %d, want unset when the feature is off", fd)
	}
}

// TestPrepareSharedPacketRewriteRefusesICMPEchoReplyWithoutAPrefix mirrors
// TestPrepareTCRefusesICMPEchoReplyWithoutAPrefix: requesting icmp_echo_reply=reply
// with no ForceIntercept prefix at all must fail cleanly, leaking no FDs -- the
// whole backend (not just the icmp_echo_reply half of it) is torn down, since
// PrepareSharedPacketRewrite's own contract is to return nil on any error.
func TestPrepareSharedPacketRewriteRefusesICMPEchoReplyWithoutAPrefix(t *testing.T) {
	before := openFDCount(t)
	policy := newTestSharedNetworkForceInterceptPolicy(t, "")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, true))
	if err == nil {
		_ = backend.Close()
		t.Fatal("icmp_echo_reply=reply with no ForceIntercept prefix at all was reported as success")
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("open file descriptors went from %d to %d; PrepareSharedPacketRewrite did not fully release "+
			"what it loaded before the icmp_echo_reply refusal", before, after)
	}
}
