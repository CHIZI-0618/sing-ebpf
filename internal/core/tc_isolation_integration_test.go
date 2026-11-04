//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"context"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTCPListenerDirectFallbackIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify listener fallback before program exposure")
	policy, err := CompileActionPolicy(ActionPolicy{
		Local: ActionScope{Default: DecisionIntercept}, Shared: ActionScope{Default: DecisionIntercept}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{ListenerPort: 65530, EnableLocal: true,
		EnableShared: true, EnableIPv4: true, EnableTCP: true, EnableUDP: true, Policy: policy, AssignmentCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	old := backend.runtime.programs[tcProgramDeliveryIngress]
	backend.access.Lock()
	err = backend.useDirectTCPListenersLocked()
	backend.access.Unlock()
	if err != nil {
		backend.Close()
		t.Fatal(err)
	}
	if backend.TCPListenerLookupMode() != "direct" || old.FD() != -1 || backend.DeliveryIngressProgramFD() < 0 {
		t.Fatal("fallback did not replace/close the old delivery program")
	}
	backend.access.Lock()
	err = backend.useDirectTCPListenersLocked()
	backend.access.Unlock()
	if err == nil {
		t.Fatal("fallback replaced an exposed program")
	}
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTCIsolatedVerifierIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load tuple-preserving namespace TC programs")
	for _, legacy := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, process := range []bool{false, true} {
				policy, err := CompileActionPolicy(ActionPolicy{
					Local: ActionScope{Default: DecisionIntercept}, Shared: ActionScope{Default: DecisionIntercept}})
				if err != nil {
					t.Fatal(err)
				}
				backend, err := prepareTC(TCConfig{ListenerPort: 65530, EnableLocal: true, EnableShared: true,
					EnableIPv4: true, EnableLocalIPv6: true, EnableSharedIPv6: true, EnableTCP: tcp, EnableUDP: true,
					Policy: policy, TrackProcess: process, AssignmentCapacity: 32}, legacy)
				if err != nil {
					t.Fatalf("legacy=%v tcp=%v process=%v: %+v", legacy, tcp, process, err)
				}
				if backend.DeliveryIngressProgramFD() < 0 || backend.IsolatedReturnProgramFD() < 0 {
					t.Fatal("missing isolation programs")
				}
				if err = backend.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestTCPListenerMixedLookupModeIntegration(t *testing.T) {
	requireEBPFIntegration(t, "register a plain TCP and an MPTCP listener")
	policy, err := CompileActionPolicy(ActionPolicy{Local: ActionScope{Default: DecisionIntercept}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{ListenerPort: 65530, EnableLocal: true, EnableIPv4: true,
		EnableLocalIPv6: true, EnableTCP: true, EnableUDP: true, Policy: policy, AssignmentCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if backend.TCPListenerLookupMode() != "sockmap" {
		t.Skip("the kernel has no SOCKMAP listener lookup")
	}
	register := func(network string, mptcp bool) int {
		var config net.ListenConfig
		config.SetMultipathTCP(mptcp)
		listener, err := config.Listen(context.Background(), network, ":0")
		if err != nil {
			t.Skipf("listen on %s: %v", network, err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		raw, err := listener.(*net.TCPListener).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var protocol int
		var registerErr error
		if err = raw.Control(func(fd uintptr) {
			protocol, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			registerErr = backend.RegisterTCPListener(network == "tcp6", int(fd))
		}); err != nil {
			t.Fatal(err)
		}
		if registerErr != nil {
			t.Fatal(registerErr)
		}
		return protocol
	}
	register("tcp4", false)
	if mode := backend.TCPListenerLookupMode(); mode != "sockmap" {
		t.Fatalf("lookup mode with a plain listener = %q, want sockmap", mode)
	}
	if register("tcp6", true) != unix.IPPROTO_MPTCP {
		t.Skip("the kernel does not provide MPTCP listeners")
	}
	if mode := backend.TCPListenerLookupMode(); mode != "mixed" {
		t.Fatalf("lookup mode = %q, want mixed", mode)
	}
	// Re-registering the IPv4 family with an MPTCP listener clears its
	// SOCKMAP slot, leaving both families found by port.
	register("tcp4", true)
	if mode := backend.TCPListenerLookupMode(); mode != "direct" {
		t.Fatalf("lookup mode = %q, want direct", mode)
	}
}
