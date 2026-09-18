//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestKernelProgramNames(t *testing.T) {
	// Keep this list aligned with program_name.go. Besides enforcing the kernel
	// limit, global uniqueness prevents diagnostics from making two concurrently
	// loaded roles look like the same program.
	names := []string{
		kernelProgramNameCgroupConnect4,
		kernelProgramNameCgroupSendmsg4,
		kernelProgramNameCgroupRecvmsg4,
		kernelProgramNameCgroupConnect6,
		kernelProgramNameCgroupSendmsg6,
		kernelProgramNameCgroupRecvmsg6,
		kernelProgramNameCgroupRelease,
		kernelProgramNameTCLocalEthernet,
		kernelProgramNameTCLocalRawIP,
		kernelProgramNameTCSharedEthernet,
		kernelProgramNameTCSharedRawIP,
		kernelProgramNameTCDelivery,
		kernelProgramNameSharedIngress,
		kernelProgramNameSharedEgress,
		kernelProgramNameICMPLocalEthernet,
		kernelProgramNameICMPLocalRawIP,
		kernelProgramNameICMPSharedEthernet,
		kernelProgramNameICMPSharedRawIP,
		kernelProgramNameSelfCreate,
		kernelProgramNameSelfRelease,
		kernelProgramNameSelfConnect4,
		kernelProgramNameSelfConnect6,
		kernelProgramNameSelfSendmsg4,
		kernelProgramNameSelfSendmsg6,
		kernelProgramNameProcessConnect4,
		kernelProgramNameProcessConnect6,
		kernelProgramNameProcessSendmsg4,
		kernelProgramNameProcessSendmsg6,
		kernelProgramNameProcessRelease,
		kernelProgramNameReleaseProbe,
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if len(name) == 0 || len(name) > 15 {
			t.Fatalf("invalid kernel program name %q: length %d", name, len(name))
		}
		if _, exists := seen[name]; exists {
			t.Fatalf("duplicate kernel program name: %s", name)
		}
		seen[name] = struct{}{}
	}
}
