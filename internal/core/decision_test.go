//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"testing"
)

func TestDecisionValues(t *testing.T) {
	if !DecisionPass.Valid() || !DecisionIntercept.Valid() {
		t.Fatal("supported eBPF decisions must be valid")
	}
	if Decision(2).Valid() {
		t.Fatal("unknown eBPF decision was accepted")
	}
}

func TestCompileActionPolicyUsesFinalActions(t *testing.T) {
	policy, err := CompileActionPolicy(ActionPolicy{
		EnableTCP: true,
		EnableUDP: true,
		Local: ActionScope{
			Default: DecisionIntercept,
			UID:     []UIDDecision{{Start: 10000, End: 10010, Action: DecisionPass}},
			DestinationCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.168.0.0/16"),
				Action: DecisionPass,
			}},
		},
		Shared: ActionScope{
			Default: DecisionIntercept,
			SourceCIDR: []CIDRDecision{{
				Prefix: netip.MustParsePrefix("192.0.2.0/24"),
				Action: DecisionIntercept,
			}},
			SourceMAC: []MACDecision{{
				Address: MACAddress{2, 0, 0, 0, 0, 1},
				Action:  DecisionPass,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.local.ExcludeUID) != 1 || policy.local.ExcludeUID[0].Start != 10000 {
		t.Fatalf("UID pass action was not compiled into the local decision: %+v", policy.local.ExcludeUID)
	}
	if len(policy.localInitialBypass.ipv4) != 1 || !policy.localInitialBypass.ipv4[0].Addr().Is4() {
		t.Fatalf("destination pass action was not compiled into the local bypass map: %+v", policy.localInitialBypass)
	}
	if len(policy.includeSource.ipv4) != 1 || len(policy.excludeSourceMAC) != 1 {
		t.Fatalf("shared source actions were not compiled: include=%+v exclude_mac=%+v", policy.includeSource, policy.excludeSourceMAC)
	}
}
