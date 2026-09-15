//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
)

// newTestForceInterceptPolicy compiles a CompiledPolicy carrying only what
// PrepareICMPEchoReply needs: ForceIntercept prefixes and the protocol toggles
// prepareTC's own validation requires.
func newTestForceInterceptPolicy(t *testing.T, forceInterceptIPv4, forceInterceptIPv6 string) CompiledPolicy {
	t.Helper()
	config := PolicyConfig{EnableTCP: true}
	if forceInterceptIPv4 != "" {
		config.ForceInterceptIPv4 = netip.MustParsePrefix(forceInterceptIPv4)
	}
	if forceInterceptIPv6 != "" {
		config.ForceInterceptIPv6 = netip.MustParsePrefix(forceInterceptIPv6)
	}
	policy, err := CompilePolicy(config)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return policy
}

// TestPrepareTCLoadsICMPEchoReplyWhenRequested drives PrepareTC with
// ICMPEchoReply set against a real kernel: real maps, real programs, a real
// verifier pass (already proven separately for the object itself; this
// confirms the Go-side loading and control-map population reach the same
// result end to end).
func TestPrepareTCLoadsICMPEchoReplyWhenRequested(t *testing.T) {
	policy := newTestForceInterceptPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:  12345,
		EnableLocal:   true,
		EnableIPv4:    true,
		EnableTCP:     true,
		Policy:        policy,
		ICMPEchoReply: true,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if !backend.ICMPEchoReplyEnabled() {
		t.Fatal("ICMPEchoReplyEnabled() = false after requesting icmp_echo_reply=reply")
	}
	for _, framing := range []TCLinkFraming{TCLinkFramingEthernet, TCLinkFramingRawIP} {
		if fd := backend.ICMPEchoLocalReplyProgramFD(framing); fd < 0 {
			t.Fatalf("local reply program FD for framing %v is unset", framing)
		}
		if fd := backend.ICMPEchoSharedReplyProgramFD(framing); fd < 0 {
			t.Fatalf("shared reply program FD for framing %v is unset", framing)
		}
	}
}

// TestPrepareTCRefusesICMPEchoReplyWithoutAPrefix is the Go-side mirror of the
// native object's own refusal to run with nothing to match: requesting
// icmp_echo_reply=reply with no ForceIntercept prefix compiled at all must fail, not load
// a control map that can never enable itself.
func TestPrepareTCRefusesICMPEchoReplyWithoutAPrefix(t *testing.T) {
	before := openFDCount(t)
	policy := newTestForceInterceptPolicy(t, "", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:  12345,
		EnableLocal:   true,
		EnableIPv4:    true,
		EnableTCP:     true,
		Policy:        policy,
		ICMPEchoReply: true,
	})
	if err == nil {
		_ = backend.Close()
		t.Fatal("icmp_echo_reply=reply with no ForceIntercept prefix at all was reported as success")
	}
	after := openFDCount(t)
	if after > before {
		t.Fatalf("open file descriptors went from %d to %d; the icmp_echo_reply maps and "+
			"programs loaded before the refusal were not released", before, after)
	}
}

// TestPrepareTCWithoutICMPEchoReplyLoadsNothingExtra confirms the default,
// feature-off path: ICMPEchoReplyEnabled is false and none of the icmp_echo_reply
// program accessors return a usable FD, without touching the object at all.
func TestPrepareTCWithoutICMPEchoReplyLoadsNothingExtra(t *testing.T) {
	policy := newTestForceInterceptPolicy(t, "198.18.0.0/15", "")
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 12345,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if backend.ICMPEchoReplyEnabled() {
		t.Fatal("ICMPEchoReplyEnabled() = true without requesting icmp_echo_reply=reply")
	}
	if fd := backend.ICMPEchoLocalReplyProgramFD(TCLinkFramingEthernet); fd >= 0 {
		t.Fatalf("local reply program FD = %d, want unset when the feature is off", fd)
	}
}
