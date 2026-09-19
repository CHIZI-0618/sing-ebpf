//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// Decision is the only policy result understood by sing-ebpf. The library
// does not interpret why a rule was selected (for example DNS, FakeIP,
// routing, or a sing-box rule-set); the caller supplies the final action.
type Decision uint8

const (
	DecisionPass Decision = iota
	DecisionIntercept
)

// Valid reports whether d is one of the two supported data-plane actions.
func (d Decision) Valid() bool {
	return d == DecisionPass || d == DecisionIntercept
}

// CIDRDecision is a CIDR match with an already compiled final action.
type CIDRDecision struct {
	Prefix netip.Prefix
	Action Decision
}

// PortDecision is a protocol/port match with an already compiled final
// action. Protocol uses the IANA IP protocol number (6 for TCP, 17 for UDP).
type PortDecision struct {
	Protocol uint8
	Port     uint16
	Action   Decision
}

// UIDDecision is a UID range match with an already compiled final action.
type UIDDecision struct {
	Start  uint32
	End    uint32
	Action Decision
}

// MACDecision is a source MAC match with an already compiled final action.
type MACDecision struct {
	Address MACAddress
	Action  Decision
}

// ActionScope contains only match primitives and their final actions. It does
// not encode include/exclude, DNS, FakeIP, or rule-set semantics.
type ActionScope struct {
	Default         Decision
	UID             []UIDDecision
	SourceCIDR      []CIDRDecision
	SourceMAC       []MACDecision
	DestinationCIDR []CIDRDecision
	DestinationPort []PortDecision
}

// ActionPolicy is the policy input for the action-only API. The caller owns
// configuration semantics and supplies the final action for every rule.
type ActionPolicy struct {
	EnableTCP bool
	EnableUDP bool
	Local     ActionScope
	Shared    ActionScope
}

func compileDestinationPassDecisions(decisions []CIDRDecision) (BypassCIDRPolicy, error) {
	prefixes := make([]netip.Prefix, 0, len(decisions))
	for _, decision := range decisions {
		if !decision.Prefix.IsValid() || !decision.Action.Valid() {
			return BypassCIDRPolicy{}, E.New("invalid eBPF destination decision")
		}
		if decision.Action != DecisionPass {
			return BypassCIDRPolicy{}, E.New("destination decision updates require pass actions")
		}
		prefixes = append(prefixes, decision.Prefix)
	}
	return CompileBypassCIDRPolicy(prefixes)
}
