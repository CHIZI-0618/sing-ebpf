//go:build with_ebpf && (linux || android)

package core

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// TestSharedNetworkStatsReadCleanlyWithNoFailures checks native counters on
// a backend that has not processed a packet.
func TestSharedNetworkStatsReadCleanlyWithNoFailures(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	if tokenFailures, err := backend.TokenReservationFailures(); err != nil {
		t.Fatalf("TokenReservationFailures: %v", err)
	} else if tokenFailures != 0 {
		t.Fatalf("TokenReservationFailures = %d, want 0 on a backend that has processed nothing", tokenFailures)
	}
	if rewriteFailures, err := backend.RewriteFailures(); err != nil {
		t.Fatalf("RewriteFailures: %v", err)
	} else if rewriteFailures != 0 {
		t.Fatalf("RewriteFailures = %d, want 0 on a backend that has processed nothing", rewriteFailures)
	}
	for name, read := range map[string]func() (uint64, error){
		"IngressPasses":         backend.IngressPasses,
		"EgressPasses":          backend.EgressPasses,
		"IngressFragmentPasses": backend.IngressFragmentPasses,
		"EgressFragmentPasses":  backend.EgressFragmentPasses,
	} {
		if value, err := read(); err != nil {
			t.Fatalf("%s: %v", name, err)
		} else if value != 0 {
			t.Fatalf("%s = %d, want 0 on a backend that has processed nothing", name, value)
		}
	}
}

func TestSharedNetworkStatsAllCategoriesIndependent(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	statsMap := backend.runtime.maps["shared_stats"]
	if statsMap == nil {
		t.Fatal("shared_stats map is unavailable")
	}
	readers := []struct {
		name  string
		index uint32
		read  func() (uint64, error)
	}{
		{"token reservation failure", sharedNetworkStatTokenReservationFailure, backend.TokenReservationFailures},
		{"rewrite failure", sharedNetworkStatRewriteFailure, backend.RewriteFailures},
		{"ingress pass", sharedNetworkStatIngressPass, backend.IngressPasses},
		{"egress pass", sharedNetworkStatEgressPass, backend.EgressPasses},
		{"ingress fragment pass", sharedNetworkStatIngressFragmentPass, backend.IngressFragmentPasses},
		{"egress fragment pass", sharedNetworkStatEgressFragmentPass, backend.EgressFragmentPasses},
	}
	for expectedIndex, expected := range readers {
		perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
		perCPU[0] = uint64(expectedIndex + 1)
		if err = statsMap.Put(expected.index, perCPU); err != nil {
			t.Fatalf("seed %s: %v", expected.name, err)
		}
	}
	for expectedIndex, expected := range readers {
		value, readErr := expected.read()
		if readErr != nil {
			t.Fatalf("read %s: %v", expected.name, readErr)
		}
		if value != uint64(expectedIndex+1) {
			t.Fatalf("%s = %d, want %d", expected.name, value, expectedIndex+1)
		}
	}
}

// TestSharedNetworkStatsIndependent proves the two categories are read from
// distinct indices, not the same counter under two names: incrementing the
// underlying kernel map at TokenReservationFailure's index directly must not
// move RewriteFailures.
func TestSharedNetworkStatsIndependent(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(nil, newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	statsMap := backend.runtime.maps["shared_stats"]
	if statsMap == nil {
		t.Fatal("shared_stats map is unavailable")
	}
	perCPU := make([]uint64, CiliumEBPF.MustPossibleCPU())
	perCPU[0] = 1
	if err := statsMap.Put(sharedNetworkStatTokenReservationFailure, perCPU); err != nil {
		t.Fatalf("seed shared_stats[token_reservation_failure]: %v", err)
	}

	tokenFailures, err := backend.TokenReservationFailures()
	if err != nil {
		t.Fatalf("TokenReservationFailures: %v", err)
	}
	if tokenFailures != 1 {
		t.Fatalf("TokenReservationFailures = %d, want 1", tokenFailures)
	}
	rewriteFailures, err := backend.RewriteFailures()
	if err != nil {
		t.Fatalf("RewriteFailures: %v", err)
	}
	if rewriteFailures != 0 {
		t.Fatalf("RewriteFailures = %d, want 0 -- it must not read the token-reservation-failure slot", rewriteFailures)
	}
}
