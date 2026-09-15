//go:build with_ebpf && (linux || android)

package core

import (
	"net/netip"
	"sync"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// ICMPEchoReplyBackend answers ICMP Echo Request packets destined to the
// configured force-intercept prefixes with a locally synthesized Echo Reply. It is a
// standalone backend, independent of TCBackend and SharedPacketRewriteBackend,
// because icmp_echo_reply.bpf.c is its own native object with its own control
// map (see that file's own comment for why it is not folded into either
// tc.bpf.c or shared_network.bpf.c) and because more than one caller needs
// to host it: TCBackend does, for local TC and shared socket_assign, and so
// does shared.data_plane: packet_rewrite, which has no TCBackend of its own
// at all. Prior to this type existing, only TCBackend could load this
// object, which meant a packet_rewrite-only inbound (no local interception,
// no socket_assign) had nothing to host the responder on even though the
// native object itself has always supported a "shared reply" path.
type ICMPEchoReplyBackend struct {
	access    sync.RWMutex
	runtime   *tcRuntime
	controlFD int
	closed    bool
}

const (
	icmpEchoReplyProgramLocalEthernet = iota
	icmpEchoReplyProgramLocalRawIP
	icmpEchoReplyProgramSharedEthernet
	icmpEchoReplyProgramSharedRawIP
	icmpEchoReplyProgramCount
)

const (
	icmpEchoReplyFlagEnabled            = 1 << 0
	icmpEchoReplyFlagIPv4               = 1 << 1
	icmpEchoReplyFlagLocalIPv6          = 1 << 2
	icmpEchoReplyFlagSharedIPv6         = 1 << 3
	icmpEchoReplyFlagForceInterceptIPv4 = 1 << 4
	icmpEchoReplyFlagForceInterceptIPv6 = 1 << 5
)

// These three mirror native/icmp_echo_reply.bpf.c's SB_ICMP_ECHO_REPLY_STAT_* indices
// and SB_ICMP_ECHO_REPLY_STAT_COUNT field for field; there is no generated
// binding for either side's constants, so this comment is the ABI contract
// between them. See that file's own comment on icmp_echo_reply_stats for why
// ordinary non-ICMP traffic on the same interface is never counted here at
// all: PassThrough only ever counts an ICMP/ICMPv6 Echo Request this object
// examined and declined to answer.
const (
	icmpEchoReplyStatReply          uint32 = 0
	icmpEchoReplyStatPassThrough    uint32 = 1
	icmpEchoReplyStatRewriteFailure uint32 = 2
	icmpEchoReplyStatCount                 = 3
)

// icmpEchoReplyControl mirrors struct sb_icmp_echo_reply_control in
// native/icmp_echo_reply.bpf.c field for field; the _Static_assert in that file
// is this struct's ABI contract.
type icmpEchoReplyControl struct {
	Flags                    uint32
	ForceInterceptIPv4Prefix [4]byte
	ForceInterceptIPv4Mask   [4]byte
	ForceInterceptIPv6Prefix [16]byte
	ForceInterceptIPv6Mask   [16]byte
}

// loadICMPEchoReplyResources loads the object's two maps and four programs. The
// maps are kept even though this object has no config-shaped sizing to do,
// because loadObjectMaps drops any map not named in its overrides — the
// overrides here exist to rename and place them, not to resize them.
func loadICMPEchoReplyResources() (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := map[string]mapSpecOverride{
		"icmp_echo_reply_control": {name: "sb_icmp_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
		"icmp_echo_reply_stats":   {name: "sb_icmp_stat", mapType: CiliumEBPF.PerCPUArray, maxEntries: icmpEchoReplyStatCount},
	}
	maps, err := loadObjectMaps(loadICMPEchoReply, mapOverrides)
	if err != nil {
		return nil, nil, err
	}
	selections := []programSelection{
		{section: "classifier/icmp_echo_reply_local_reply_ethernet", name: "sb_icmp_lcl_e"},
		{section: "classifier/icmp_echo_reply_local_reply_raw_ip", name: "sb_icmp_lcl_r"},
		{section: "classifier/icmp_echo_reply_shared_reply_ethernet", name: "sb_icmp_shr_e"},
		{section: "classifier/icmp_echo_reply_shared_reply_raw_ip", name: "sb_icmp_shr_r"},
	}
	programs, err := loadObjectPrograms(loadICMPEchoReply, maps, selections)
	if err != nil {
		return nil, nil, E.Errors(err, closeMaps(maps))
	}
	return maps, programs, nil
}

// PrepareICMPEchoReply loads the icmp_echo_reply object and populates its control
// map. ipv4Enabled, localIPv6Enabled, and sharedIPv6Enabled mirror the same
// address-family toggles the caller's own backend (TCBackend or
// SharedPacketRewriteBackend) was configured with — this object answers on
// whichever families and roles its caller actually intercepts, not a
// second, independently-configured policy. At least one of forceInterceptIPv4 or
// forceInterceptIPv6 must be valid; callers are expected to have already refused
// icmp_echo_reply=reply with neither configured (see the consumer's config
// validation), but this is checked again here so a backend can never exist
// in a state that can never match anything.
func PrepareICMPEchoReply(
	ipv4Enabled bool,
	localIPv6Enabled bool,
	sharedIPv6Enabled bool,
	forceInterceptIPv4 netip.Prefix,
	forceInterceptIPv6 netip.Prefix,
) (*ICMPEchoReplyBackend, error) {
	if !forceInterceptIPv4.IsValid() && !forceInterceptIPv6.IsValid() {
		return nil, E.New("ICMP echo reply requires a configured force-intercept prefix")
	}
	maps, programs, err := loadICMPEchoReplyResources()
	if err != nil {
		return nil, E.Cause(err, "load icmp_echo_reply eBPF resources")
	}
	control := icmpEchoReplyControl{}
	if ipv4Enabled {
		control.Flags |= icmpEchoReplyFlagIPv4
	}
	if localIPv6Enabled {
		control.Flags |= icmpEchoReplyFlagLocalIPv6
	}
	if sharedIPv6Enabled {
		control.Flags |= icmpEchoReplyFlagSharedIPv6
	}
	if forceInterceptIPv4.IsValid() {
		control.Flags |= icmpEchoReplyFlagForceInterceptIPv4
		control.ForceInterceptIPv4Prefix = forceInterceptIPv4.Addr().As4()
		control.ForceInterceptIPv4Mask = prefixMask4(forceInterceptIPv4.Bits())
	}
	if forceInterceptIPv6.IsValid() {
		control.Flags |= icmpEchoReplyFlagForceInterceptIPv6
		control.ForceInterceptIPv6Prefix = forceInterceptIPv6.Addr().As16()
		control.ForceInterceptIPv6Mask = prefixMask16(forceInterceptIPv6.Bits())
	}
	control.Flags |= icmpEchoReplyFlagEnabled
	controlFD := maps["icmp_echo_reply_control"].FD()
	zero := uint32(0)
	if err = updateMap(controlFD, unsafe.Pointer(&zero), unsafe.Pointer(&control)); err != nil {
		closeErr := closeObjectResources(programs, maps)
		return nil, E.Errors(E.Cause(err, "populate icmp_echo_reply eBPF control"), closeErr)
	}
	return &ICMPEchoReplyBackend{
		runtime:   &tcRuntime{maps: maps, programs: programs},
		controlFD: controlFD,
	}, nil
}

func (b *ICMPEchoReplyBackend) program(index int) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed || index < 0 || index >= len(b.runtime.programs) {
		return nil
	}
	return b.runtime.programs[index]
}

func (b *ICMPEchoReplyBackend) programFD(index int) int {
	program := b.program(index)
	if program == nil {
		return -1
	}
	return program.FD()
}

func (b *ICMPEchoReplyBackend) LocalReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(icmpEchoReplyProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(icmpEchoReplyProgramLocalRawIP)
	default:
		return -1
	}
}

func (b *ICMPEchoReplyBackend) LocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(icmpEchoReplyProgramLocalEthernet)
	case TCLinkFramingRawIP:
		return b.program(icmpEchoReplyProgramLocalRawIP)
	default:
		return nil
	}
}

func (b *ICMPEchoReplyBackend) SharedReplyProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(icmpEchoReplyProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(icmpEchoReplyProgramSharedRawIP)
	default:
		return -1
	}
}

func (b *ICMPEchoReplyBackend) SharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(icmpEchoReplyProgramSharedEthernet)
	case TCLinkFramingRawIP:
		return b.program(icmpEchoReplyProgramSharedRawIP)
	default:
		return nil
	}
}

// ReplyCount, PassThroughCount, and RewriteFailureCount read
// icmp_echo_reply_stats' three categories -- see that map's own doc comment in
// native/icmp_echo_reply.bpf.c. Each is a full PERCPU_ARRAY sum, computed fresh
// on every call; callers polling frequently should cache accordingly.
func (b *ICMPEchoReplyBackend) ReplyCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatReply)
}

func (b *ICMPEchoReplyBackend) PassThroughCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatPassThrough)
}

func (b *ICMPEchoReplyBackend) RewriteFailureCount() (uint64, error) {
	return b.stat(icmpEchoReplyStatRewriteFailure)
}

func (b *ICMPEchoReplyBackend) stat(index uint32) (uint64, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.closed {
		return 0, errBackendClosed
	}
	statsMap := b.runtime.maps["icmp_echo_reply_stats"]
	if statsMap == nil {
		return 0, errBackendClosed
	}
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

// Close releases the object's maps and programs. Safe to call on a nil
// receiver or more than once.
func (b *ICMPEchoReplyBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return closeObjectResources(b.runtime.programs, b.runtime.maps)
}
