//go:build with_ebpf && (linux || android)

package core

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// TestProbeKernelICMPEchoReplyOnlyWhenRequested confirms the probe report gains
// icmp_echo_reply findings only when asked, and that on a real kernel (this is
// not a table of assumed results — ProbeKernel runs the real
// features.HaveProgramHelper checks) every helper the object needs comes
// back supported, matching the real verifier-accepted load proven in
// tc_icmp_echo_reply_test.go and the real attach proven in
// the runtime package's netns tests.
func TestProbeKernelICMPEchoReplyOnlyWhenRequested(t *testing.T) {
	without, err := ProbeKernel(KernelProbeOptions{Mode: KernelProbeModeLocal, LocalDataPlane: KernelProbeDataPlaneTC})
	if err != nil {
		t.Fatalf("probe without icmp_echo_reply: %v", err)
	}
	for _, finding := range without.Findings {
		if finding.Scope == "icmp_echo_reply" {
			t.Fatalf("found a icmp_echo_reply finding (%+v) without asking for one", finding)
		}
	}

	with, err := ProbeKernel(KernelProbeOptions{
		Mode: KernelProbeModeLocal, LocalDataPlane: KernelProbeDataPlaneTC,
		ICMPEchoReply: true,
	})
	if err != nil {
		t.Fatalf("probe with icmp_echo_reply: %v", err)
	}
	found := 0
	foundPerCPUScratch := false
	foundPacketWrite := false
	for _, finding := range with.Findings {
		if finding.Scope != "icmp_echo_reply" {
			continue
		}
		found++
		switch finding.Feature {
		case "BPF map type " + CiliumEBPF.PerCPUArray.String():
			foundPerCPUScratch = true
		case "bpf_skb_store_bytes for SchedCLS":
			foundPacketWrite = true
		}
		if finding.Status == KernelProbeFail {
			t.Fatalf("icmp_echo_reply finding reported unsupported on this kernel: %+v", finding)
		}
	}
	if found == 0 {
		t.Fatal("no icmp_echo_reply findings were reported after asking for them")
	}
	if !foundPerCPUScratch || !foundPacketWrite {
		t.Fatalf("icmp_echo_reply object requirements are incomplete: per_cpu_array=%v skb_store_bytes=%v", foundPerCPUScratch, foundPacketWrite)
	}
}
