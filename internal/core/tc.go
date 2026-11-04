//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	tcProgramLocalEgressEthernet = iota
	tcProgramLocalEgressRawIP
	tcProgramSharedIngressEthernet
	tcProgramSharedIngressRawIP
	tcProgramDeliveryIngress
	tcProgramIsolatedReturn
	tcProgramCount
)

const (
	// Assignment maps hold active local/shared flow state. Keep enough headroom
	// for bursts without reserving the oversized legacy Linux default on every
	// device. Platform-specific compact capacity is selected by sing-box.
	tcAssignmentCapacity        = 32768
	CompactTCAssignmentCapacity = 8192
	tcPortPolicyCapacity        = 4096
)

const (
	tcStatSocketLookupFailure uint32 = iota
	tcStatSKAssignFailure
	tcStatAssignmentUpdateFailure
	tcStatLocalFragmentPass
	tcStatSharedFragmentPass
	tcStatReturnUpdateFailure
	tcStatReturnConflict
	tcStatReturnLookupFailure
	tcStatCount
)

// TCStats contains counters collected on native TC error and fragment pass
// paths. Values are cumulative for the lifetime of the backend and are summed
// across CPUs.
type TCStats struct {
	SocketLookupFailures     uint64
	SKAssignFailures         uint64
	AssignmentUpdateFailures uint64
	LocalFragmentPasses      uint64
	SharedFragmentPasses     uint64
	ReturnUpdateFailures     uint64
	ReturnConflicts          uint64
	ReturnLookupFailures     uint64
}

// DefaultTCRoutingMark is used only by standalone backend tests and callers
// that do not install policy routing. The TC data plane selects a free mark
// before enabling the backend.
const DefaultTCRoutingMark uint32 = 1 << 29

const (
	tcFlagIPv4 = 1 << iota
	tcFlagLocalIPv6
	tcFlagTCP
	tcFlagUDP
)

const tcFlagSharedIPv6 = 1 << 18
const (
	tcFlagLocalBypassPort  = 1 << 20
	tcFlagSharedBypassPort = 1 << 21
	tcFlagSharedBypassIPv4 = 1 << 22
	tcFlagSharedBypassIPv6 = 1 << 23
)

const (
	tcListenerTCP4 = iota
	tcListenerTCP6
	tcListenerCount
)

const (
	TCPathShared   = 1
	TCPathDelivery = 2
)

type TCConfig struct {
	ListenerPort       uint16
	EnableLocal        bool
	EnableShared       bool
	EnableIPv4         bool
	EnableLocalIPv6    bool
	EnableSharedIPv6   bool
	EnableTCP          bool
	EnableUDP          bool
	DeliveryInterface  uint32
	Policy             CompiledPolicy
	RoutingMark        uint32
	SelfBypassMap      *CiliumEBPF.Map
	TrackProcess       bool
	AssignmentCapacity uint32
	// ICMPEchoReply loads the independent icmp_echo_reply object (see
	// tc_icmp_echo_reply.go) and attaches it wherever this TC data plane already
	// attaches local or shared filters. Left false, prepareTC never touches
	// that object, and this backend requires nothing beyond what it already
	// requires today.
	ICMPEchoReply bool
}

type PortRange struct {
	Start uint16
	End   uint16
}

type tcPortKey struct {
	Protocol uint8
	Reserved uint8
	Port     uint16
}

type tcControl struct {
	Enabled           uint32
	Flags             uint32
	DeliveryInterface uint32
	RoutingMark       uint32
	ListenerPort      uint16
	ReservedPolicy    [2]uint16
	DeliveryMAC       MACAddress
	Reserved          uint16
}

type tcAssignKey struct {
	Family             uint8
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
	Reserved           uint16
	InterfaceIndex     uint32
	SourceAddress      [16]byte
	DestinationAddress [16]byte
}

type TCAssignment struct {
	SocketCookie   uint64
	LastSeenNS     uint64
	InterfaceIndex uint32
	SourceMAC      MACAddress
	Path           uint8
	SourceMACValid uint8
	Generation     uint32
}

// TCAssignmentSweepResult describes one bounded cleanup pass. Entries are
// removed after their kernel timestamp exceeds maxIdle and an immediate
// value/generation recheck still matches. The per-map scan budget also applies
// on batch-capable kernels; Complete covers assignment, return and fragments.
type TCAssignmentSweepResult struct {
	ReturnUsage      MapUsage
	ReturnUsageKnown bool
	ReturnScanned    uint32
	ReturnRemoved    uint32
	Usage            MapUsage
	Scanned          uint32
	Removed          uint32
	Complete         bool
	// UsageKnown is true only after a complete traversal. A bounded partial
	// traversal must not be interpreted as an empty map by callers.
	UsageKnown bool
	Pressure   bool
	// Failure classifies a failed maintenance pass without requiring callers
	// to parse platform-specific errno text. An empty value means the pass
	// completed (or is a normal partial traversal).
	Failure    string
	FailureMap string
}

const (
	TCAssignmentSweepFailureClosed = "closed"
	TCAssignmentSweepFailureScan   = "scan"
	TCAssignmentSweepFailureLookup = "lookup"
	TCAssignmentSweepFailureDelete = "delete"
)

type tcAssignmentSweepEntry struct {
	key   tcAssignKey
	value TCAssignment
}

type tcRuntime struct {
	maps     map[string]*CiliumEBPF.Map
	programs []*CiliumEBPF.Program
}

type TCBackend struct {
	access                    sync.RWMutex
	health                    backendHealth
	runtime                   *tcRuntime
	tcpListenerMap            bool
	programsExposed           bool
	control                   tcControl
	controlMapFD              int
	assignmentMapFD           int
	assignmentCapacity        uint32
	assignmentSweepAccess     sync.Mutex
	assignmentSweepRemoved    uint32
	returnSweepRemoved        uint32
	assignmentSweepScratch    mapScanScratch[tcAssignKey, TCAssignment]
	assignmentSweepCandidates []tcAssignmentSweepEntry
	selfMapExternal           bool
	bypassIPv4                []netip.Prefix
	bypassIPv6                []netip.Prefix
	sharedBypassIPv4          []netip.Prefix
	sharedBypassIPv6          []netip.Prefix
	hostIPv4                  [][4]byte
	hostIPv6                  [][16]byte
	// icmpEchoReply is nil unless TCConfig.ICMPEchoReply was set; see
	// tc_icmp_echo_reply.go. It is a standalone backend (ICMPEchoReplyBackend) rather
	// than fields inline here because shared.data_plane: packet_rewrite hosts
	// the same native object with no TCBackend of its own to hold it in.
	icmpEchoReply              *ICMPEchoReplyBackend
	returnAccess               sync.Mutex
	returnReferences           map[tcReturnReference]uint32
	returnSweepScratch         mapScanScratch[tcAssignKey, tcReturnValue]
	returnFragmentSweepScratch mapScanScratch[tcAssignKey, tcReturnValue]
	// tcpListenerModes records, per listener family, whether the registered
	// listener is in the SOCKMAP or is found by port because it is MPTCP.
	tcpListenerModes [tcListenerCount]uint8
}

func PrepareTC(config TCConfig) (*TCBackend, error) {
	return prepareTC(config, false)
}

func prepareTC(config TCConfig, forceLegacyTCP bool) (*TCBackend, error) {
	if config.ListenerPort == 0 {
		return nil, E.New("invalid TC eBPF listener port")
	}
	if !config.EnableIPv4 && !config.EnableLocalIPv6 && !config.EnableSharedIPv6 {
		return nil, E.New("TC eBPF backend has no enabled address family")
	}
	if !config.EnableTCP && !config.EnableUDP {
		return nil, E.New("TC eBPF backend has no enabled protocol")
	}
	if !config.EnableLocal && !config.EnableShared {
		return nil, E.New("TC eBPF backend has no enabled data path")
	}
	if config.RoutingMark == 0 {
		config.RoutingMark = DefaultTCRoutingMark
	}
	if config.AssignmentCapacity == 0 {
		config.AssignmentCapacity = tcAssignmentCapacity
	} else if config.AssignmentCapacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid TC eBPF assignment map capacity: ", config.AssignmentCapacity)
	}
	policy := config.Policy
	var err error
	uidEntries := policy.uidEntries
	includeIPv4, includeIPv6 := policy.includeSource.ipv4, policy.includeSource.ipv6
	excludeIPv4, excludeIPv6 := policy.excludeSource.ipv4, policy.excludeSource.ipv6
	if err = checkLPMTriePolicyCompatibility(
		"TC eBPF UID and source CIDR",
		len(uidEntries)+len(includeIPv4)+len(includeIPv6)+len(excludeIPv4)+len(excludeIPv6),
	); err != nil {
		return nil, err
	}
	memlockErr := raiseMemlockLimit()
	mapOverrides := map[string]mapSpecOverride{
		"tc_control":             {name: "sb_tc_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
		"tc_listener_sockets":    {name: "sb_tc_listen", mapType: CiliumEBPF.SockMap, maxEntries: 2},
		"tc_assignment":          {name: "sb_tc_assign", mapType: CiliumEBPF.LRUHash, maxEntries: config.AssignmentCapacity},
		"tc_stats":               {name: "sb_tc_stats", mapType: CiliumEBPF.PerCPUArray, maxEntries: tcStatCount},
		"tc_uid_policy":          {name: "sb_tc_uid", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(uidEntries)), 1), flags: bpfFlagNoPrealloc},
		"tc_local_bypass_ipv4":   {name: "sb_tc_lbypass4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxDestinationCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_local_bypass_ipv6":   {name: "sb_tc_lbypass6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxDestinationCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_shared_bypass_ipv4":  {name: "sb_tc_sbypass4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxDestinationCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_shared_bypass_ipv6":  {name: "sb_tc_sbypass6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxDestinationCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_include_source_ipv4": {name: "sb_tc_insrc4", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(includeIPv4)), 1), flags: bpfFlagNoPrealloc},
		"tc_include_source_ipv6": {name: "sb_tc_insrc6", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(includeIPv6)), 1), flags: bpfFlagNoPrealloc},
		"tc_exclude_source_ipv4": {name: "sb_tc_exsrc4", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(excludeIPv4)), 1), flags: bpfFlagNoPrealloc},
		"tc_exclude_source_ipv6": {name: "sb_tc_exsrc6", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(excludeIPv6)), 1), flags: bpfFlagNoPrealloc},
		"tc_include_source_mac":  {name: "sb_tc_insmac", mapType: CiliumEBPF.Hash, maxEntries: sourceMACMapCapacity(len(policy.includeSourceMAC))},
		"tc_exclude_source_mac":  {name: "sb_tc_exsmac", mapType: CiliumEBPF.Hash, maxEntries: sourceMACMapCapacity(len(policy.excludeSourceMAC))},
		"tc_host_ipv4":           {name: "sb_tc_host4", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_host_ipv6":           {name: "sb_tc_host6", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_local_bypass_port":   {name: "sb_tc_lport", mapType: CiliumEBPF.Hash, maxEntries: max(uint32(len(policy.localBypassPortEntries)), 1), flags: bpfFlagNoPrealloc},
		"tc_shared_bypass_port":  {name: "sb_tc_sport", mapType: CiliumEBPF.Hash, maxEntries: max(uint32(len(policy.sharedBypassPortEntries)), 1), flags: bpfFlagNoPrealloc},
	}
	addForceMapOverrides(mapOverrides, "tc_local", "sb_tc_lforce", policy.localForce)
	addForceMapOverrides(mapOverrides, "tc_shared", "sb_tc_sforce", policy.sharedForce)
	if config.EnableLocal {
		selfMapCapacity := uint32(selfBypassSocketCapacity)
		if config.SelfBypassMap != nil {
			// This map is replaced before programs are loaded. Avoid transiently
			// allocating a second full-size LRU map during every backend rebuild.
			selfMapCapacity = 1
		}
		mapOverrides["tc_self_sockets"] = mapSpecOverride{
			name: "sb_self_sockets", mapType: CiliumEBPF.LRUHash, maxEntries: selfMapCapacity,
		}
	}
	legacyTCP := forceLegacyTCP || !config.EnableTCP
	mapOverrides["tc_return"] = mapSpecOverride{name: "sb_tc_return", mapType: CiliumEBPF.Hash, maxEntries: config.AssignmentCapacity}
	mapOverrides["tc_return_frag"] = mapSpecOverride{name: "sb_tc_rfrag", mapType: CiliumEBPF.LRUHash, maxEntries: min(config.AssignmentCapacity, 1024)}
	maps, loadedPrograms, err := loadTCResources(config, mapOverrides, legacyTCP)
	if err != nil && config.EnableTCP && !forceLegacyTCP {
		legacyTCP = true
		maps, loadedPrograms, err = loadTCResources(config, mapOverrides, true)
	}
	if err != nil {
		return nil, explainBPFPermissionError(err, memlockErr)
	}
	controlValue := tcControl{
		Flags:             tcFlags(config, policy),
		DeliveryInterface: config.DeliveryInterface,
		RoutingMark:       config.RoutingMark,
		ListenerPort:      config.ListenerPort,
	}
	if len(includeIPv4)+len(includeIPv6) > 0 {
		controlValue.Flags |= 1 << 12
	}
	if len(excludeIPv4)+len(excludeIPv6) > 0 {
		controlValue.Flags |= 1 << 13
	}
	if len(policy.includeSourceMAC) > 0 {
		controlValue.Flags |= 1 << 14
	}
	if len(policy.excludeSourceMAC) > 0 {
		controlValue.Flags |= 1 << 15
	}
	if len(policy.localInitialBypass.ipv4) > 0 {
		controlValue.Flags |= 1 << 8
	}
	if len(policy.localInitialBypass.ipv6) > 0 {
		controlValue.Flags |= 1 << 9
	}
	if len(policy.sharedInitialBypass.ipv4) > 0 {
		controlValue.Flags |= tcFlagSharedBypassIPv4
	}
	if len(policy.sharedInitialBypass.ipv6) > 0 {
		controlValue.Flags |= tcFlagSharedBypassIPv6
	}
	backend := &TCBackend{
		runtime:            &tcRuntime{maps: maps, programs: loadedPrograms},
		tcpListenerMap:     config.EnableTCP && !legacyTCP,
		control:            controlValue,
		controlMapFD:       maps["tc_control"].FD(),
		assignmentMapFD:    maps["tc_assignment"].FD(),
		assignmentCapacity: config.AssignmentCapacity,
		selfMapExternal:    config.EnableLocal && config.SelfBypassMap != nil,
	}
	// From here, backend owns maps and loadedPrograms: giving up on either of the
	// steps below has to close it rather than just returning the step's error, or
	// what it already holds leaks. Close's own error is folded into the one
	// reported rather than discarded — calling Close does not by itself mean the
	// maps and programs it held were actually released, and an error out of it is
	// exactly the case where they may not have been.
	if err = backend.updateControlLocked(); err != nil {
		return nil, E.Errors(err, backend.Close())
	}
	if err = populateCompiledPolicyMaps(policyMapTargets{
		Scope:          "TC eBPF",
		LocalForceIPv4: maps["tc_local_force4"], LocalForceIPv6: maps["tc_local_force6"],
		SharedForceIPv4: maps["tc_shared_force4"], SharedForceIPv6: maps["tc_shared_force6"],
		UID:               maps["tc_uid_policy"],
		LocalPort:         maps["tc_local_bypass_port"],
		SharedPort:        maps["tc_shared_bypass_port"],
		LocalBypassIPv4:   maps["tc_local_bypass_ipv4"],
		LocalBypassIPv6:   maps["tc_local_bypass_ipv6"],
		SharedBypassIPv4:  maps["tc_shared_bypass_ipv4"],
		SharedBypassIPv6:  maps["tc_shared_bypass_ipv6"],
		IncludeSourceIPv4: maps["tc_include_source_ipv4"],
		IncludeSourceIPv6: maps["tc_include_source_ipv6"],
		ExcludeSourceIPv4: maps["tc_exclude_source_ipv4"],
		ExcludeSourceIPv6: maps["tc_exclude_source_ipv6"],
		IncludeSourceMAC:  maps["tc_include_source_mac"],
		ExcludeSourceMAC:  maps["tc_exclude_source_mac"],
	}, policy); err != nil {
		return nil, E.Errors(err, backend.Close())
	}
	if config.ICMPEchoReply {
		backend.icmpEchoReply, err = PrepareICMPEchoReply(
			config.EnableIPv4, config.EnableLocalIPv6, config.EnableSharedIPv6, policy,
		)
		if err != nil {
			return nil, E.Errors(err, backend.Close())
		}
	}
	return backend, nil
}

func loadTCResources(config TCConfig, baseOverrides map[string]mapSpecOverride, legacyTCP bool) (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := make(map[string]mapSpecOverride, len(baseOverrides))
	for name, override := range baseOverrides {
		mapOverrides[name] = override
	}
	if legacyTCP {
		delete(mapOverrides, "tc_listener_sockets")
	}
	maps, err := loadObjectMaps(loadTC, mapOverrides)
	if err != nil {
		return nil, nil, err
	}
	externalSelfMap := config.EnableLocal && config.SelfBypassMap != nil
	if externalSelfMap {
		createdMap := maps["tc_self_sockets"]
		maps["tc_self_sockets"] = config.SelfBypassMap
		_ = createdMap.Close()
	}
	selections := make([]programSelection, 0, tcProgramCount)
	programIndexes := make([]int, 0, tcProgramCount)
	if config.EnableLocal {
		ethernet, rawIP := "classifier/local_egress_ethernet_isolated", "classifier/local_egress_raw_ip_isolated"
		if config.TrackProcess {
			ethernet += "_process"
			rawIP += "_process"
		}
		selections = append(selections, programSelection{section: ethernet, kernelProgramName: kernelProgramNameTCLocalEthernet}, programSelection{section: rawIP, kernelProgramName: kernelProgramNameTCLocalRawIP})
		programIndexes = append(programIndexes, tcProgramLocalEgressEthernet, tcProgramLocalEgressRawIP)
	}
	if config.EnableShared {
		selections = append(selections, programSelection{section: "classifier/shared_ingress_ethernet_isolated", kernelProgramName: kernelProgramNameTCSharedEthernet}, programSelection{section: "classifier/shared_ingress_raw_ip_isolated", kernelProgramName: kernelProgramNameTCSharedRawIP})
		programIndexes = append(programIndexes, tcProgramSharedIngressEthernet, tcProgramSharedIngressRawIP)
	}
	delivery := "classifier/isolated_delivery"
	if !config.EnableTCP {
		delivery += "_udp"
	} else if legacyTCP {
		delivery += "_legacy"
	}
	selections = append(selections, programSelection{section: delivery, kernelProgramName: kernelProgramNameTCDelivery}, programSelection{section: "classifier/isolated_return", kernelProgramName: "sb_tc_return"})
	programIndexes = append(programIndexes, tcProgramDeliveryIngress, tcProgramIsolatedReturn)
	loadedPrograms, err := loadObjectPrograms(loadTC, maps, selections)
	if err != nil {
		if externalSelfMap {
			// The caller's map is deleted from this map first so closeMaps below
			// does not reach it: it is not this function's to close, whether or
			// not the rest of the load succeeded.
			delete(maps, "tc_self_sockets")
		}
		// closeMaps closing something here does not mean the map it held is
		// actually gone — the same caveat as backend.Close() above — but a
		// failure out of it is still worth reporting alongside the load failure
		// that made this function give up, rather than being dropped.
		return nil, nil, E.Errors(err, closeMaps(maps))
	}
	programs := make([]*CiliumEBPF.Program, tcProgramCount)
	for index, program := range loadedPrograms {
		programs[programIndexes[index]] = program
	}
	return maps, programs, nil
}

func (b *TCBackend) SetRoutingMark(mark uint32) error {
	if mark == 0 {
		return E.New("invalid TC eBPF routing mark")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	previous := b.control.RoutingMark
	b.control.RoutingMark = mark
	if err := b.updateControlLocked(); err != nil {
		b.control.RoutingMark = previous
		return err
	}
	return nil
}

func tcFlags(config TCConfig, policy CompiledPolicy) uint32 {
	return policyVector{
		EnableTCP:           config.EnableTCP,
		EnableUDP:           config.EnableUDP,
		EnableIPv4:          config.EnableIPv4,
		EnableLocalIPv6:     config.EnableLocalIPv6,
		EnableSharedIPv6:    config.EnableSharedIPv6,
		UIDPolicy:           len(policy.uidEntries) > 0 || policy.uidDefaultBypass,
		UIDDefaultBypass:    policy.uidDefaultBypass,
		SharedDefaultBypass: policy.sharedDefaultBypass,
		LocalBypassPort:     len(policy.localBypassPortEntries) > 0,
		SharedBypassPort:    len(policy.sharedBypassPortEntries) > 0,
		ForceInterceptIPv4:  (len(policy.localForce.ipv4)+len(policy.sharedForce.ipv4) > 0),
		ForceInterceptIPv6:  (len(policy.localForce.ipv6)+len(policy.sharedForce.ipv6) > 0),
		IncludeSource:       len(policy.includeSource.ipv4)+len(policy.includeSource.ipv6) > 0,
		ExcludeSource:       len(policy.excludeSource.ipv4)+len(policy.excludeSource.ipv6) > 0,
		IncludeSourceMAC:    len(policy.includeSourceMAC) > 0,
		ExcludeSourceMAC:    len(policy.excludeSourceMAC) > 0,
	}.tcFlags()
}

func (b *TCBackend) requireUsableLocked() error {
	return b.health.requireUsable(b.runtime != nil)
}

// RequiresRebuild reports whether a previous operation's internal rollback
// itself failed, leaving this backend's maps and control flags no longer
// agreeing with each other and with no known-good state left to compute the
// next incremental update from -- invalidateLocked already disabled the
// data path when this happened. Every operation on it fails from then on,
// so a caller retrying one can stop instead of repeating work that cannot
// succeed. Mirrors SharedPacketRewriteBackend.RequiresRebuild.
func (b *TCBackend) RequiresRebuild() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.health.rebuildRequired != nil
}

func (b *TCBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}

// invalidateLocked marks the backend unusable after a policy update failed and
// its rollback failed too. The policy maps and the control flags that gate them
// no longer agree and there is no longer a known-good state to compute the next
// incremental update from, so the data path is switched off and every later
// operation is refused until the backend is rebuilt. This mirrors
// SharedPacketRewriteBackend.invalidateLocked.
func (b *TCBackend) invalidateLocked(operation string, cause error) error {
	rebuildRequired := b.health.invalidate("TC", operation)
	b.control.Enabled = 0
	disableErr := b.updateControlLocked()
	if disableErr != nil {
		disableErr = E.Cause(disableErr, "disable unusable TC backend")
	}
	return E.Errors(cause, disableErr, rebuildRequired)
}

func (b *TCBackend) updateControlLocked() error {
	key := uint32(0)
	if err := updateMap(b.controlMapFD, unsafe.Pointer(&key), unsafe.Pointer(&b.control)); err != nil {
		return eBPFOperationError("update TC eBPF control", err)
	}
	return nil
}

func (b *TCBackend) Enable() error {
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	previousEnabled := b.control.Enabled
	b.control.Enabled = 1
	if err := b.updateControlLocked(); err != nil {
		b.control.Enabled = previousEnabled
		return err
	}
	return nil
}

func (b *TCBackend) Disable() error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	previousEnabled := b.control.Enabled
	b.control.Enabled = 0
	if err := b.updateControlLocked(); err != nil {
		b.control.Enabled = previousEnabled
		return err
	}
	return nil
}

func (b *TCBackend) SetDeliveryInterface(interfaceIndex uint32, hardwareAddress MACAddress) error {
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	previousInterface := b.control.DeliveryInterface
	previousHardwareAddress := b.control.DeliveryMAC
	b.control.DeliveryInterface = interfaceIndex
	b.control.DeliveryMAC = hardwareAddress
	if err := b.updateControlLocked(); err != nil {
		b.control.DeliveryInterface = previousInterface
		b.control.DeliveryMAC = previousHardwareAddress
		return err
	}
	return nil
}

const (
	tcListenerUnregistered = iota
	tcListenerInSockmap
	tcListenerByPort
)

// RegisterTCPListener places a plain TCP listener in the SOCKMAP. A SOCKMAP
// rejects MPTCP sockets, which Go listeners use by default since Go 1.24, so
// an MPTCP listener is left out of it and the programs find its TCP subflow
// listener by port instead; that requires a wildcard bind. Registration must
// precede exposing/attaching any program. Any other listener rejection can
// still select direct lookup even when a synthetic probe or SOCKMAP creation
// succeeded (socket protocol and namespace both matter).
func (b *TCBackend) RegisterTCPListener(ipv6 bool, fd int) error {
	b.access.Lock()
	defer b.access.Unlock()
	if !b.tcpListenerMap {
		return nil
	}
	if fd < 0 {
		return E.New("invalid TC eBPF listener socket")
	}
	key := uint32(tcListenerTCP4)
	if ipv6 {
		key = tcListenerTCP6
	}
	value := uint32(fd)
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	listenerMapFD := b.runtime.maps["tc_listener_sockets"].FD()
	if protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL); err == nil && protocol == unix.IPPROTO_MPTCP {
		// Deleting an empty SOCKMAP slot reports EINVAL rather than ENOENT.
		if err = deleteMap(listenerMapFD, unsafe.Pointer(&key)); err != nil &&
			!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
			return E.Cause(err, "unregister previous TC eBPF TCP listener")
		}
		b.tcpListenerModes[key] = tcListenerByPort
		return nil
	}
	if err := updateMap(listenerMapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) && !b.programsExposed && b.control.Enabled == 0 {
			if fallbackErr := b.useDirectTCPListenersLocked(); fallbackErr == nil {
				return nil
			} else {
				return E.Errors(E.Cause(err, "register TC eBPF TCP listener"), fallbackErr)
			}
		}
		return E.Cause(err, "register TC eBPF TCP listener")
	}
	b.tcpListenerModes[key] = tcListenerInSockmap
	return nil
}

func (b *TCBackend) useDirectTCPListenersLocked() error {
	if b.programsExposed || b.control.Enabled != 0 {
		return E.New("cannot replace exposed TC listener programs")
	}
	var selections []programSelection
	var indexes []int
	add := func(index int, section, name string) {
		if b.runtime.programs[index] != nil {
			indexes = append(indexes, index)
			selections = append(selections, programSelection{section: section, kernelProgramName: name})
		}
	}
	add(tcProgramDeliveryIngress, "classifier/isolated_delivery_legacy", kernelProgramNameTCDelivery)
	programs, err := loadObjectPrograms(loadTC, b.runtime.maps, selections)
	if err != nil {
		return err
	}
	var closeErr error
	for n, index := range indexes {
		closeErr = E.Errors(closeErr, b.runtime.programs[index].Close())
		b.runtime.programs[index] = programs[n]
	}
	b.tcpListenerMap = false
	return closeErr
}

// TCPListenerLookupMode reports "sockmap" or "direct", or "mixed" when one
// registered listener family is in the SOCKMAP and the other is found by port.
func (b *TCBackend) TCPListenerLookupMode() string {
	b.access.RLock()
	defer b.access.RUnlock()
	if !b.tcpListenerMap {
		return "direct"
	}
	var inSockmap, byPort bool
	for _, mode := range b.tcpListenerModes {
		switch mode {
		case tcListenerInSockmap:
			inSockmap = true
		case tcListenerByPort:
			byPort = true
		}
	}
	switch {
	case byPort && inSockmap:
		return "mixed"
	case byPort:
		return "direct"
	default:
		return "sockmap"
	}
}

func (b *TCBackend) LookupAssignment(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, remove bool) (TCAssignment, error) {
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		return TCAssignment{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCAssignment{}, errBackendClosed
	}
	var assignment TCAssignment
	if err = lookupMap(b.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&assignment)); err != nil {
		return TCAssignment{}, err
	}
	if remove {
		_ = deleteMap(b.assignmentMapFD, unsafe.Pointer(&key))
	}
	return assignment, nil
}

// RemoveAssignmentIfMatch removes one TC assignment only when the value still
// belongs to the session which is being closed. UDP assignment keys can be
// reused quickly, so an unconditional delete from a timeout callback could
// remove a newer session's entry. A missing entry or a value mismatch is a
// successful no-op; LRU eviction remains the fallback for entries which are
// not observed by userspace during their lifetime. The match ignores
// LastSeenNS, which the programs refresh while the session is active; see
// sameTCAssignment.
func (b *TCBackend) RemoveAssignmentIfMatch(
	protocol uint8,
	source, destination netip.AddrPort,
	interfaceIndex uint32,
	expected TCAssignment,
) (bool, error) {
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		return false, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return false, errBackendClosed
	}
	var current TCAssignment
	if err = lookupMap(b.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&current)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if !sameTCAssignment(current, expected) {
		return false, nil
	}
	if err = deleteMap(b.assignmentMapFD, unsafe.Pointer(&key)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// sameTCAssignment reports whether two values are the same assignment. The
// programs refresh LastSeenNS in place while the assignment is unchanged and
// advance Generation whenever they rewrite it, so a session's value differs
// from the current one in LastSeenNS alone until another session replaces it.
func sameTCAssignment(left, right TCAssignment) bool {
	left.LastSeenNS, right.LastSeenNS = 0, 0
	return left == right
}

// SweepAssignments performs a bounded control-plane cleanup pass for TC
// assignments using the kernel-maintained activity timestamp. The value is
// rechecked before deletion, preventing an old session from deleting a newer
// assignment for the same key.
func (b *TCBackend) SweepAssignments(maxIdle time.Duration, fallbackBudget uint32) (TCAssignmentSweepResult, error) {
	if b == nil {
		return TCAssignmentSweepResult{Failure: TCAssignmentSweepFailureClosed}, errBackendClosed
	}
	if maxIdle <= 0 || fallbackBudget == 0 {
		return TCAssignmentSweepResult{}, unix.EINVAL
	}
	// Native activity writes are coalesced for one second. Never interpret
	// that intentionally coarse timestamp as proof that an active flow is idle.
	maxIdle = max(maxIdle, 2*time.Second)
	b.assignmentSweepAccess.Lock()
	defer b.assignmentSweepAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || b.runtime.maps["tc_assignment"] == nil {
		return TCAssignmentSweepResult{Failure: TCAssignmentSweepFailureClosed}, errBackendClosed
	}
	result := TCAssignmentSweepResult{Usage: MapUsage{Capacity: b.assignmentCapacity}, FailureMap: "sb_tc_assign"}
	now := monotonicNowNS()
	maxIdleNS := uint64(maxIdle)
	staleBefore := now - min(now, maxIdleNS)
	b.assignmentSweepCandidates = b.assignmentSweepCandidates[:0]
	scan, err := b.assignmentSweepScratch.scan(
		b.runtime.maps["tc_assignment"], b.assignmentCapacity, fallbackBudget,
		func(key tcAssignKey, value TCAssignment) {
			if value.LastSeenNS != 0 && value.LastSeenNS <= staleBefore {
				b.assignmentSweepCandidates = append(b.assignmentSweepCandidates, tcAssignmentSweepEntry{key: key, value: value})
			}
		},
	)
	if err != nil {
		result.Failure = TCAssignmentSweepFailureScan
		return result, err
	}
	result.Scanned, result.Complete = scan.Scanned, scan.Complete
	if scan.Restarted {
		b.assignmentSweepRemoved = 0
	}
	for _, candidate := range b.assignmentSweepCandidates {
		var current TCAssignment
		if err = lookupMap(b.assignmentMapFD, unsafe.Pointer(&candidate.key), unsafe.Pointer(&current)); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			result.Failure = TCAssignmentSweepFailureLookup
			return result, err
		}
		if current != candidate.value {
			continue
		}
		if err = deleteMap(b.assignmentMapFD, unsafe.Pointer(&candidate.key)); err != nil && !errors.Is(err, unix.ENOENT) {
			result.Failure = TCAssignmentSweepFailureDelete
			return result, err
		}
		result.Removed++
		b.assignmentSweepRemoved++
	}
	if result.Complete {
		result.Usage.Entries = scan.Entries - min(scan.Entries, b.assignmentSweepRemoved)
		b.assignmentSweepRemoved = 0
		result.UsageKnown = true
		result.Pressure = uint64(result.Usage.Entries)*100 >= uint64(result.Usage.Capacity)*70
	}
	if err = b.sweepReturnRoutesLocked(max(maxIdle, time.Second), fallbackBudget, &result); err != nil {
		return result, err
	}
	if result.Failure == "" {
		result.FailureMap = ""
	}
	return result, nil
}

// Stats reads the native TC error counters on demand. It performs one map
// lookup per counter and never runs from a background worker or timer.
func (b *TCBackend) Stats() (TCStats, error) {
	if b == nil {
		return TCStats{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCStats{}, errBackendClosed
	}
	statsMap := b.runtime.maps["tc_stats"]
	if statsMap == nil {
		return TCStats{}, errBackendClosed
	}
	read := func(index uint32) (uint64, error) {
		var perCPU []uint64
		if err := statsMap.Lookup(&index, &perCPU); err != nil {
			return 0, err
		}
		var total uint64
		for _, value := range perCPU {
			total += value
		}
		return total, nil
	}
	var stats TCStats
	var err error
	if stats.SocketLookupFailures, err = read(tcStatSocketLookupFailure); err != nil {
		return TCStats{}, err
	}
	if stats.SKAssignFailures, err = read(tcStatSKAssignFailure); err != nil {
		return TCStats{}, err
	}
	if stats.AssignmentUpdateFailures, err = read(tcStatAssignmentUpdateFailure); err != nil {
		return TCStats{}, err
	}
	if stats.LocalFragmentPasses, err = read(tcStatLocalFragmentPass); err != nil {
		return TCStats{}, err
	}
	if stats.SharedFragmentPasses, err = read(tcStatSharedFragmentPass); err != nil {
		return TCStats{}, err
	}
	if stats.ReturnUpdateFailures, err = read(tcStatReturnUpdateFailure); err != nil {
		return TCStats{}, err
	}
	if stats.ReturnConflicts, err = read(tcStatReturnConflict); err != nil {
		return TCStats{}, err
	}
	if stats.ReturnLookupFailures, err = read(tcStatReturnLookupFailure); err != nil {
		return TCStats{}, err
	}
	return stats, nil
}

// UpdateLocalDestinationDecisions applies final local pass decisions. The
// backend does not interpret the reason for a pass action.
func (b *TCBackend) UpdateLocalDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	policy, err := compileDestinationPassDecisions(decisions)
	if err != nil {
		return false, err
	}
	return b.updateDestinationCIDRPolicy(policy, false)
}

// UpdateSharedDestinationDecisions applies final shared pass decisions. The
// backend does not interpret the reason for a pass action.
func (b *TCBackend) UpdateSharedDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	policy, err := compileDestinationPassDecisions(decisions)
	if err != nil {
		return false, err
	}
	return b.updateDestinationCIDRPolicy(policy, true)
}

func (b *TCBackend) updateDestinationCIDRPolicy(policy dualStackCIDRPrefixes, shared bool) (bool, error) {
	if len(policy.ipv4) > maxDestinationCIDRPolicyEntries || len(policy.ipv6) > maxDestinationCIDRPolicyEntries {
		return false, E.New("TC eBPF bypass CIDR policy exceeds map capacity")
	}
	if err := checkLPMTriePolicyCompatibility("TC eBPF bypass CIDR", len(policy.ipv4)+len(policy.ipv6)); err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return false, err
	}
	ipv4MapName, ipv6MapName := "tc_local_bypass_ipv4", "tc_local_bypass_ipv6"
	previousIPv4, previousIPv6 := b.bypassIPv4, b.bypassIPv6
	flagIPv4, flagIPv6 := uint32(1<<8), uint32(1<<9)
	if shared {
		ipv4MapName, ipv6MapName = "tc_shared_bypass_ipv4", "tc_shared_bypass_ipv6"
		previousIPv4, previousIPv6 = b.sharedBypassIPv4, b.sharedBypassIPv6
		flagIPv4, flagIPv6 = tcFlagSharedBypassIPv4, tcFlagSharedBypassIPv6
	}
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps[ipv4MapName],
		b.runtime.maps[ipv6MapName],
		dualStackCIDRPrefixes{previousIPv4, previousIPv6},
		policy,
		"TC ",
		"bypass CIDR",
	)
	if err != nil {
		// The replace helper rolls its own partial work back. When that rollback
		// fails too the maps hold neither policy and there is no state left to
		// compute the next incremental update from, so the backend has to be
		// marked unusable here rather than waiting for the control update below.
		if policyRollbackFailed(err) {
			return false, b.invalidateLocked("bypass CIDR policy", err)
		}
		return false, err
	}
	previousFlags := b.control.Flags
	if shared {
		b.sharedBypassIPv4 = slices.Clone(policy.ipv4)
		b.sharedBypassIPv6 = slices.Clone(policy.ipv6)
	} else {
		b.bypassIPv4 = slices.Clone(policy.ipv4)
		b.bypassIPv6 = slices.Clone(policy.ipv6)
	}
	if len(policy.ipv4) > 0 {
		b.control.Flags |= flagIPv4
	} else {
		b.control.Flags &^= flagIPv4
	}
	if len(policy.ipv6) > 0 {
		b.control.Flags |= flagIPv6
	} else {
		b.control.Flags &^= flagIPv6
	}
	if err = b.updateControlLocked(); err != nil {
		// The policy maps are already live while the control flags that gate them
		// are not, and the programs read the flag before the map, so leaving this
		// half-applied changes what the data plane matches. Put the maps back.
		_, restoreErr := replaceDualStackCIDRPolicy(
			b.runtime.maps[ipv4MapName],
			b.runtime.maps[ipv6MapName],
			dualStackCIDRPrefixes(policy),
			dualStackCIDRPrefixes{previousIPv4, previousIPv6},
			"TC ",
			"bypass CIDR",
		)
		if restoreErr != nil {
			// The maps hold neither the old nor the new policy now. Restoring the
			// in-memory fields would make the next incremental update diff against
			// a state the kernel is not in and skip the entries that need
			// repairing, so leave them and refuse further use instead.
			return false, b.invalidateLocked(
				"bypass CIDR policy",
				policyUpdateError(err, restoreErr),
			)
		}
		if shared {
			b.sharedBypassIPv4, b.sharedBypassIPv6 = previousIPv4, previousIPv6
		} else {
			b.bypassIPv4, b.bypassIPv6 = previousIPv4, previousIPv6
		}
		b.control.Flags = previousFlags
		return false, err
	}
	return changed, nil
}

func (b *TCBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostAddresses(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("TC eBPF host address policy exceeds map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	err := replaceHostAddressPolicy(
		b.runtime.maps["tc_host_ipv4"],
		b.runtime.maps["tc_host_ipv6"],
		b.hostIPv4,
		b.hostIPv6,
		ipv4,
		ipv6,
	)
	if err != nil {
		// The replace helper rolls its own partial work back. When that rollback
		// fails too the maps hold neither policy and there is no state left to
		// compute the next incremental update from, so the backend has to be
		// marked unusable here rather than waiting for the control update below.
		if policyRollbackFailed(err) {
			return b.invalidateLocked("host address policy", err)
		}
		return err
	}
	previousIPv4, previousIPv6 := b.hostIPv4, b.hostIPv6
	previousFlags := b.control.Flags
	b.hostIPv4 = slices.Clone(ipv4)
	b.hostIPv6 = slices.Clone(ipv6)
	if len(b.hostIPv4) > 0 {
		b.control.Flags |= 1 << 16
	} else {
		b.control.Flags &^= 1 << 16
	}
	if len(b.hostIPv6) > 0 {
		b.control.Flags |= 1 << 17
	} else {
		b.control.Flags &^= 1 << 17
	}
	if err = b.updateControlLocked(); err != nil {
		// host_selected() checks SB_TC_FLAG_HOST_IPV4/IPV6 before it looks the
		// address up, so a populated map behind a stale flag is not a bookkeeping
		// mismatch: the host-address check is skipped entirely. Roll the maps back
		// to the state the flags still describe.
		restoreErr := replaceHostAddressPolicy(
			b.runtime.maps["tc_host_ipv4"],
			b.runtime.maps["tc_host_ipv6"],
			ipv4,
			ipv6,
			previousIPv4,
			previousIPv6,
		)
		if restoreErr != nil {
			return b.invalidateLocked(
				"host address policy",
				policyUpdateError(err, restoreErr),
			)
		}
		b.hostIPv4, b.hostIPv6 = previousIPv4, previousIPv6
		b.control.Flags = previousFlags
		return err
	}
	return nil
}

func makeTCAssignKey(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32) (tcAssignKey, error) {
	var key tcAssignKey
	if !source.IsValid() || !destination.IsValid() || source.Addr().Is4() != destination.Addr().Is4() {
		return key, E.New("invalid TC eBPF assignment tuple")
	}
	key.Protocol = protocol
	key.SourcePort = source.Port()
	key.DestinationPort = destination.Port()
	key.InterfaceIndex = interfaceIndex
	if source.Addr().Is4() {
		key.Family = addressFamilyIPv4
		source4 := source.Addr().As4()
		destination4 := destination.Addr().As4()
		copy(key.SourceAddress[:4], source4[:])
		copy(key.DestinationAddress[:4], destination4[:])
	} else {
		key.Family = addressFamilyIPv6
		key.SourceAddress = source.Addr().As16()
		key.DestinationAddress = destination.Addr().As16()
	}
	return key, nil
}

func (b *TCBackend) LocalEgressProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(tcProgramLocalEgressEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(tcProgramLocalEgressRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) LocalEgressProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(tcProgramLocalEgressEthernet)
	case TCLinkFramingRawIP:
		return b.program(tcProgramLocalEgressRawIP)
	default:
		return nil
	}
}

func (b *TCBackend) SharedIngressProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(tcProgramSharedIngressEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(tcProgramSharedIngressRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) SharedIngressProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(tcProgramSharedIngressEthernet)
	case TCLinkFramingRawIP:
		return b.program(tcProgramSharedIngressRawIP)
	default:
		return nil
	}
}

func (b *TCBackend) DeliveryIngressProgramFD() int { return b.programFD(tcProgramDeliveryIngress) }
func (b *TCBackend) IsolatedReturnProgramFD() int  { return b.programFD(tcProgramIsolatedReturn) }

func (b *TCBackend) programFD(index int) int {
	if b == nil {
		return -1
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil || index < 0 || index >= len(b.runtime.programs) || b.runtime.programs[index] == nil {
		return -1
	}
	b.programsExposed = true
	return b.runtime.programs[index].FD()
}

func (b *TCBackend) program(index int) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil || index < 0 || index >= len(b.runtime.programs) {
		return nil
	}
	b.programsExposed = true
	return b.runtime.programs[index]
}

func (b *TCBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	b.control.Enabled = 0
	_ = b.updateControlLocked()
	if b.selfMapExternal {
		delete(b.runtime.maps, "tc_self_sockets")
	}
	closeErr := closeObjectResources(b.runtime.programs, b.runtime.maps)
	closeErr = E.Errors(closeErr, b.icmpEchoReply.Close())
	b.icmpEchoReply = nil
	b.runtime = nil
	b.controlMapFD = -1
	b.assignmentMapFD = -1
	b.assignmentCapacity = 0
	b.assignmentSweepCandidates = nil
	b.assignmentSweepRemoved = 0
	b.returnSweepRemoved = 0
	b.assignmentSweepScratch = mapScanScratch[tcAssignKey, TCAssignment]{}
	b.returnAccess.Lock()
	b.returnReferences = nil
	b.returnSweepScratch = mapScanScratch[tcAssignKey, tcReturnValue]{}
	b.returnFragmentSweepScratch = mapScanScratch[tcAssignKey, tcReturnValue]{}
	b.returnAccess.Unlock()
	b.selfMapExternal = false
	b.bypassIPv4 = nil
	b.bypassIPv6 = nil
	b.sharedBypassIPv4 = nil
	b.sharedBypassIPv6 = nil
	b.hostIPv4 = nil
	b.hostIPv6 = nil
	return closeErr
}
