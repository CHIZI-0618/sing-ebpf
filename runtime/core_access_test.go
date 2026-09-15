//go:build with_ebpf && (linux || android)

package runtime

import (
	"testing"

	public "github.com/CHIZI-0618/sing-ebpf"
)

func TestEmptyTCFacadeRawProgramsAreUnavailable(t *testing.T) {
	backend := rawTCBackend(new(public.TCBackend))
	for _, framing := range []public.TCLinkFraming{
		public.TCLinkFramingEthernet,
		public.TCLinkFramingRawIP,
	} {
		if fd := backend.LocalEgressProgramFD(framing); fd != -1 {
			t.Errorf("local egress program FD = %d, want -1", fd)
		}
		if program := backend.LocalEgressProgram(framing); program != nil {
			t.Errorf("local egress program = %p, want nil", program)
		}
		if fd := backend.SharedIngressProgramFD(framing); fd != -1 {
			t.Errorf("shared ingress program FD = %d, want -1", fd)
		}
		if program := backend.SharedIngressProgram(framing); program != nil {
			t.Errorf("shared ingress program = %p, want nil", program)
		}
		if fd := backend.FakeIPICMPLocalReplyProgramFD(framing); fd != -1 {
			t.Errorf("fake-IP ICMP local reply program FD = %d, want -1", fd)
		}
		if program := backend.FakeIPICMPLocalReplyProgram(framing); program != nil {
			t.Errorf("fake-IP ICMP local reply program = %p, want nil", program)
		}
		if fd := backend.FakeIPICMPSharedReplyProgramFD(framing); fd != -1 {
			t.Errorf("fake-IP ICMP shared reply program FD = %d, want -1", fd)
		}
		if program := backend.FakeIPICMPSharedReplyProgram(framing); program != nil {
			t.Errorf("fake-IP ICMP shared reply program = %p, want nil", program)
		}
	}
	if fd := backend.DeliveryIngressProgramFD(); fd != -1 {
		t.Errorf("delivery ingress program FD = %d, want -1", fd)
	}
}
