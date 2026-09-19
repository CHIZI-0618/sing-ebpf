//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

type PolicyConfig struct {
	EnableTCP           bool
	EnableUDP           bool
	Local               LocalPolicy
	SharedDNSMode       DNSMode
	SharedBypassPrivate bool
	ForceInterceptIPv4  netip.Prefix
	ForceInterceptIPv6  netip.Prefix
	IncludeSourceCIDR   []netip.Prefix
	ExcludeSourceCIDR   []netip.Prefix
	IncludeSourceMAC    []MACAddress
	ExcludeSourceMAC    []MACAddress
	LocalBypassPort     []PortRange
	SharedBypassPort    []PortRange
}

// CompiledPolicy is an immutable policy snapshot shared by all eBPF data
// planes created for one consumer. ForceInterceptIPv4 and ForceInterceptIPv6
// are opaque application-supplied destination prefixes: the library neither
// assigns their meaning nor resolves addresses within them.
type CompiledPolicy struct {
	local                   LocalPolicy
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	sharedDNSMode           DNSMode
	sharedBypassPrivate     bool
	forceInterceptIPv4      netip.Prefix
	forceInterceptIPv6      netip.Prefix
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
	localInitialBypass      dualStackCIDRPrefixes
	sharedInitialBypass     dualStackCIDRPrefixes
}

// CompileActionPolicy translates the caller's final pass/intercept rules into
// the internal map layout. The translation intentionally contains no
// sing-box concepts: a pass action becomes a bypass map entry and an
// intercept action becomes an include/force entry where the selected data
// plane supports it.
func CompileActionPolicy(config ActionPolicy) (CompiledPolicy, error) {
	if err := validateActionScope(config.Local, "local"); err != nil {
		return CompiledPolicy{}, err
	}
	if err := validateActionScope(config.Shared, "shared"); err != nil {
		return CompiledPolicy{}, err
	}
	local, localBypass, localForceIPv4, localForceIPv6, err := compileActionScope(config.Local, "local")
	if err != nil {
		return CompiledPolicy{}, err
	}
	shared, sharedBypass, sharedForceIPv4, sharedForceIPv6, err := compileActionScope(config.Shared, "shared")
	if err != nil {
		return CompiledPolicy{}, err
	}
	if localForceIPv4.IsValid() && sharedForceIPv4.IsValid() && localForceIPv4 != sharedForceIPv4 {
		return CompiledPolicy{}, E.New("local and shared IPv4 intercept prefixes differ")
	}
	if localForceIPv6.IsValid() && sharedForceIPv6.IsValid() && localForceIPv6 != sharedForceIPv6 {
		return CompiledPolicy{}, E.New("local and shared IPv6 intercept prefixes differ")
	}
	forceIPv4 := localForceIPv4
	if !forceIPv4.IsValid() {
		forceIPv4 = sharedForceIPv4
	}
	forceIPv6 := localForceIPv6
	if !forceIPv6.IsValid() {
		forceIPv6 = sharedForceIPv6
	}
	local.local.DNSMode = actionDNSMode(config.Local)
	return CompiledPolicy{
		local:                   local.local,
		uidEntries:              local.uidEntries,
		uidDefaultBypass:        local.uidDefaultBypass,
		includeSource:           shared.includeSource,
		excludeSource:           shared.excludeSource,
		includeSourceMAC:        shared.includeSourceMAC,
		excludeSourceMAC:        shared.excludeSourceMAC,
		localBypassPortEntries:  local.localBypassPortEntries,
		sharedBypassPortEntries: shared.sharedBypassPortEntries,
		forceInterceptIPv4:      forceIPv4,
		forceInterceptIPv6:      forceIPv6,
		localInitialBypass:      localBypass,
		sharedInitialBypass:     sharedBypass,
		sharedDNSMode:           actionDNSMode(config.Shared),
		sharedBypassPrivate:     false,
	}, nil
}

type compiledActionScope struct {
	local                   LocalPolicy
	uidEntries              []uidLPMKey
	uidDefaultBypass        bool
	includeSource           dualStackCIDRPrefixes
	excludeSource           dualStackCIDRPrefixes
	includeSourceMAC        []MACAddress
	excludeSourceMAC        []MACAddress
	localBypassPortEntries  []tcPortKey
	sharedBypassPortEntries []tcPortKey
}

func actionDNSMode(scope ActionScope) DNSMode {
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionIntercept {
			return DNSModeHijack
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 53 && rule.Action == DecisionPass {
			return DNSModeOff
		}
	}
	return DNSModeRespectPolicy
}

func validateActionScope(scope ActionScope, name string) error {
	if !scope.Default.Valid() {
		return E.New("invalid ", name, " eBPF default decision: ", scope.Default)
	}
	for _, rule := range scope.UID {
		if rule.Start > rule.End || !rule.Action.Valid() {
			return E.New("invalid ", name, " UID decision")
		}
	}
	for _, rule := range scope.SourceCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() {
			return E.New("invalid ", name, " source CIDR decision")
		}
	}
	for _, rule := range scope.DestinationCIDR {
		if !rule.Prefix.IsValid() || !rule.Action.Valid() {
			return E.New("invalid ", name, " destination CIDR decision")
		}
	}
	for _, rule := range scope.SourceMAC {
		if !rule.Action.Valid() {
			return E.New("invalid ", name, " source MAC decision")
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Port == 0 || !rule.Action.Valid() {
			return E.New("invalid ", name, " destination port decision")
		}
	}
	return nil
}

func compileActionScope(scope ActionScope, name string) (compiledActionScope, dualStackCIDRPrefixes, netip.Prefix, netip.Prefix, error) {
	result := compiledActionScope{}
	var bypass dualStackCIDRPrefixes
	var forceIPv4, forceIPv6 netip.Prefix
	for _, rule := range scope.UID {
		if rule.Action == DecisionPass {
			result.local.ExcludeUID = append(result.local.ExcludeUID, UIDRange{Start: rule.Start, End: rule.End})
		} else {
			result.local.IncludeUID = append(result.local.IncludeUID, UIDRange{Start: rule.Start, End: rule.End})
		}
	}
	if scope.Default == DecisionPass && len(scope.UID) > 0 {
		result.local.IncludeUIDConfigured = true
	}
	var sourceInclude, sourceExclude []netip.Prefix
	for _, rule := range scope.SourceCIDR {
		if rule.Action == DecisionPass {
			sourceExclude = append(sourceExclude, rule.Prefix)
		} else {
			sourceInclude = append(sourceInclude, rule.Prefix)
		}
	}
	result.includeSource.ipv4, result.includeSource.ipv6, _ = compileBypassCIDRPolicy(sourceInclude)
	result.excludeSource.ipv4, result.excludeSource.ipv6, _ = compileBypassCIDRPolicy(sourceExclude)
	for _, rule := range scope.SourceMAC {
		if rule.Action == DecisionPass {
			result.excludeSourceMAC = append(result.excludeSourceMAC, rule.Address)
		} else {
			result.includeSourceMAC = append(result.includeSourceMAC, rule.Address)
		}
	}
	for _, rule := range scope.DestinationCIDR {
		prefix := rule.Prefix.Masked()
		if rule.Action == DecisionPass {
			if prefix.Addr().Is4() {
				bypass.ipv4 = append(bypass.ipv4, prefix)
			} else {
				bypass.ipv6 = append(bypass.ipv6, prefix)
			}
			continue
		}
		if prefix.Addr().Is4() {
			if forceIPv4.IsValid() && forceIPv4 != prefix {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " has multiple IPv4 intercept prefixes")
			}
			forceIPv4 = prefix
		} else {
			if forceIPv6.IsValid() && forceIPv6 != prefix {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " has multiple IPv6 intercept prefixes")
			}
			forceIPv6 = prefix
		}
	}
	for _, rule := range scope.DestinationPort {
		if rule.Action != DecisionPass {
			if scope.Default == DecisionPass {
				return compiledActionScope{}, dualStackCIDRPrefixes{}, netip.Prefix{}, netip.Prefix{}, E.New(name, " cannot override a pass default with port intercept")
			}
			continue
		}
		entry := tcPortKey{Protocol: rule.Protocol, Port: rule.Port}
		if name == "shared" {
			result.sharedBypassPortEntries = append(result.sharedBypassPortEntries, entry)
		} else {
			result.localBypassPortEntries = append(result.localBypassPortEntries, entry)
		}
	}
	result.uidEntries, result.uidDefaultBypass, _ = compileUIDPolicy(result.local)
	return result, bypass, forceIPv4, forceIPv6, nil
}

func CompilePolicy(config PolicyConfig) (CompiledPolicy, error) {
	uidEntries, uidDefaultBypass, err := compileUIDPolicy(config.Local)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv4, err := normalizeAddressPrefix("IPv4 force-intercept range", config.ForceInterceptIPv4, true)
	if err != nil {
		return CompiledPolicy{}, err
	}
	forceInterceptIPv6, err := normalizeAddressPrefix("IPv6 force-intercept range", config.ForceInterceptIPv6, false)
	if err != nil {
		return CompiledPolicy{}, err
	}
	includeIPv4, includeIPv6, err := compileBypassCIDRPolicy(config.IncludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF include source CIDR policy")
	}
	excludeIPv4, excludeIPv6, err := compileBypassCIDRPolicy(config.ExcludeSourceCIDR)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile eBPF exclude source CIDR policy")
	}
	if len(includeIPv4) > maxSharedSourceCIDRPolicyEntries || len(includeIPv6) > maxSharedSourceCIDRPolicyEntries ||
		len(excludeIPv4) > maxSharedSourceCIDRPolicyEntries || len(excludeIPv6) > maxSharedSourceCIDRPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source CIDR policy exceeds map capacity")
	}
	if len(config.IncludeSourceMAC) > maxSharedSourceMACPolicyEntries ||
		len(config.ExcludeSourceMAC) > maxSharedSourceMACPolicyEntries {
		return CompiledPolicy{}, E.New("eBPF source MAC policy exceeds map capacity")
	}
	localBypassPortEntries, err := compilePortPolicy(config.LocalBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile local eBPF port bypass policy")
	}
	sharedBypassPortEntries, err := compilePortPolicy(config.SharedBypassPort, config.EnableTCP, config.EnableUDP)
	if err != nil {
		return CompiledPolicy{}, E.Cause(err, "compile shared eBPF port bypass policy")
	}
	local := config.Local
	local.IncludeUID = slices.Clone(local.IncludeUID)
	local.ExcludeUID = slices.Clone(local.ExcludeUID)
	return CompiledPolicy{
		local:                   local,
		uidEntries:              uidEntries,
		uidDefaultBypass:        uidDefaultBypass,
		sharedDNSMode:           config.SharedDNSMode,
		sharedBypassPrivate:     config.SharedBypassPrivate,
		forceInterceptIPv4:      forceInterceptIPv4,
		forceInterceptIPv6:      forceInterceptIPv6,
		includeSource:           dualStackCIDRPrefixes{ipv4: includeIPv4, ipv6: includeIPv6},
		excludeSource:           dualStackCIDRPrefixes{ipv4: excludeIPv4, ipv6: excludeIPv6},
		includeSourceMAC:        slices.Clone(config.IncludeSourceMAC),
		excludeSourceMAC:        slices.Clone(config.ExcludeSourceMAC),
		localBypassPortEntries:  localBypassPortEntries,
		sharedBypassPortEntries: sharedBypassPortEntries,
	}, nil
}

func compilePortPolicy(ranges []PortRange, enableTCP, enableUDP bool) ([]tcPortKey, error) {
	var entries []tcPortKey
	for _, portRange := range ranges {
		if portRange.Start == 0 || portRange.Start > portRange.End {
			return nil, E.New("invalid eBPF port bypass range")
		}
		for port := uint32(portRange.Start); port <= uint32(portRange.End); port++ {
			if enableTCP {
				entries = append(entries, tcPortKey{Protocol: ProtocolTCP, Port: uint16(port)})
			}
			if enableUDP {
				entries = append(entries, tcPortKey{Protocol: ProtocolUDP, Port: uint16(port)})
			}
			if len(entries) > tcPortPolicyCapacity {
				return nil, E.New("eBPF port bypass policy exceeds map capacity")
			}
		}
	}
	return entries, nil
}
