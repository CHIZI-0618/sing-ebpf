//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestDecisionValues(t *testing.T) {
	if !DecisionPass.Valid() || !DecisionIntercept.Valid() {
		t.Fatal("supported eBPF decisions must be valid")
	}
	if Decision(2).Valid() {
		t.Fatal("unknown eBPF decision was accepted")
	}
}
