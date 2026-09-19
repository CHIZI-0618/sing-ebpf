//go:build with_ebpf && (linux || android)

package core

import "net/netip"

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
