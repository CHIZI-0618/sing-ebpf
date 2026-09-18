//go:build with_ebpf && (linux || android)

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestProcessSocketOwnerABI(t *testing.T) {
	if size := unsafe.Sizeof(ProcessSocketOwner{}); size != 8 {
		t.Fatalf("unexpected process owner size: %d", size)
	}
}

func TestProcessTrackerCloseRetainsFailedLegacyAttachment(t *testing.T) {
	programLink := &retryableTestCgroupProgramLink{failures: 1}
	tracker := &ProcessTracker{links: []cgroupProgramLink{programLink}}
	if err := tracker.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if tracker.IsClosed() {
		t.Fatal("process tracker discarded a failed legacy attachment")
	}
	if err := tracker.Close(); err != nil {
		t.Fatalf("retry process tracker close: %v", err)
	}
	if !tracker.IsClosed() {
		t.Fatal("process tracker remained open after cleanup retry")
	}
}

func TestProcessTrackerHooks(t *testing.T) {
	if hooks := processTrackerHooks(ProcessTrackerConfig{}); len(hooks) != 0 {
		t.Fatalf("unexpected hooks for disabled protocols: %+v", hooks)
	}
	base := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true})
	if len(base) != 1 || base[0].attachType != CiliumEBPF.AttachCGroupInet4Connect {
		t.Fatalf("unexpected base process tracker hooks: %+v", base)
	}
	dualStackUDP := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true})
	if len(dualStackUDP) != 4 ||
		dualStackUDP[1].attachType != CiliumEBPF.AttachCGroupInet6Connect ||
		dualStackUDP[2].attachType != CiliumEBPF.AttachCGroupUDP4Sendmsg ||
		dualStackUDP[3].attachType != CiliumEBPF.AttachCGroupUDP6Sendmsg {
		t.Fatalf("unexpected dual-stack UDP process tracker hooks: %+v", dualStackUDP)
	}
	if dualStackUDP[0].kernelProgramName != kernelProgramNameProcessConnect4 ||
		dualStackUDP[1].kernelProgramName != kernelProgramNameProcessConnect6 ||
		dualStackUDP[2].kernelProgramName != kernelProgramNameProcessSendmsg4 ||
		dualStackUDP[3].kernelProgramName != kernelProgramNameProcessSendmsg6 {
		t.Fatalf("unexpected process tracker kernel program names: %+v", dualStackUDP)
	}
}

func TestProcessTrackerInstructions(t *testing.T) {
	instructions := processTrackerInstructions(1, -1, -1, false)
	if len(instructions) == 0 {
		t.Fatal("empty process tracker instructions")
	}
	if err := instructions.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
}

func TestProcessTrackerReleaseInstructions(t *testing.T) {
	instructions := processTrackerReleaseInstructions(1)
	if len(instructions) == 0 {
		t.Fatal("empty process tracker release instructions")
	}
	if err := instructions.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
}

func TestProcessTrackerReleaseCleanupMode(t *testing.T) {
	if (*ProcessTracker)(nil).ReleaseCleanup() {
		t.Fatal("nil process tracker reports socket-release cleanup")
	}
	tracker := &ProcessTracker{releaseCleanup: true}
	if !tracker.ReleaseCleanup() {
		t.Fatal("process tracker did not report socket-release cleanup")
	}
}

func TestProcessTrackerPolicyMetadata(t *testing.T) {
	tests := []struct {
		name          string
		defaultBypass bool
		matched       bool
		expected      int32
	}{
		{"include match", true, true, socketMetadataPolicyIntercept},
		{"include miss", true, false, socketMetadataPolicyBypass},
		{"exclude match", false, true, socketMetadataPolicyBypass},
		{"exclude miss", false, false, socketMetadataPolicyIntercept},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := processTrackerPolicyMetadata(test.defaultBypass, test.matched); actual != test.expected {
				t.Fatalf("unexpected metadata: got=%d expected=%d", actual, test.expected)
			}
		})
	}
}
