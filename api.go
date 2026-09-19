//go:build with_ebpf && (linux || android)

package singebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	core "github.com/CHIZI-0618/sing-ebpf/internal/core"
)

type (
	DNSMode                        = core.DNSMode
	UIDRange                       = core.UIDRange
	LocalPolicy                    = core.LocalPolicy
	MACAddress                     = core.MACAddress
	PortRange                      = core.PortRange
	PolicyConfig                   = core.PolicyConfig
	CompiledPolicy                 = core.CompiledPolicy
	BypassCIDRPolicy               = core.BypassCIDRPolicy
	CgroupMapCapacity              = core.CgroupMapCapacity
	MapUsage                       = core.MapUsage
	SharedPacketRewriteMapCapacity = core.SharedPacketRewriteMapCapacity
	OriginalDestination            = core.OriginalDestination
	CgroupBackend                  = core.CgroupBackend
	SharedPacketRewriteConfig      = core.SharedPacketRewriteConfig
	SharedPacketRewriteFlowHandle  = core.SharedPacketRewriteFlowHandle
	SharedPacketRewriteSweepResult = core.SharedPacketRewriteSweepResult
	TCAssignment                   = core.TCAssignment
	TCStats                        = core.TCStats
	TCLinkFraming                  = core.TCLinkFraming
	AttachmentInfo                 = core.AttachmentInfo
	TCNetworkInfo                  = core.TCNetworkInfo
	SelfBypassCgroupConfig         = core.SelfBypassCgroupConfig
	SelfBypassMode                 = core.SelfBypassMode
	ProcessSocketOwner             = core.ProcessSocketOwner
	ProcessTracker                 = core.ProcessTracker
	LocalRouteSet                  = core.LocalRouteSet
	KernelProbeMode                = core.KernelProbeMode
	KernelProbeDataPlane           = core.KernelProbeDataPlane
	KernelProbeStatus              = core.KernelProbeStatus
	KernelProbeImportance          = core.KernelProbeImportance
	KernelProbeOptions             = core.KernelProbeOptions
	KernelProbeFinding             = core.KernelProbeFinding
	KernelProbeReport              = core.KernelProbeReport
	RuntimeProgram                 = core.RuntimeProgram
	RuntimeState                   = core.RuntimeState
	MapOccupancy                   = core.MapOccupancy
	MapOccupancyReport             = core.MapOccupancyReport
)

const (
	ProtocolTCP = core.ProtocolTCP
	ProtocolUDP = core.ProtocolUDP

	SocketMetadataSelfBypass      = core.SocketMetadataSelfBypass
	SocketMetadataPolicyBypass    = core.SocketMetadataPolicyBypass
	SocketMetadataPolicyIntercept = core.SocketMetadataPolicyIntercept

	DNSModeHijack        = core.DNSModeHijack
	DNSModeRespectPolicy = core.DNSModeRespectPolicy
	DNSModeOff           = core.DNSModeOff

	TCPRedirectMapCapacity                   = core.TCPRedirectMapCapacity
	UDPRedirectMapCapacity                   = core.UDPRedirectMapCapacity
	UDPPeerMapCapacity                       = core.UDPPeerMapCapacity
	UDPFlowMapCapacity                       = core.UDPFlowMapCapacity
	SocketBypassMapCapacity                  = core.SocketBypassMapCapacity
	SharedPacketRewriteProxyCapacity         = core.SharedPacketRewriteProxyCapacity
	SharedPacketRewriteBypassCapacity        = core.SharedPacketRewriteBypassCapacity
	CompactSharedPacketRewriteBypassCapacity = core.CompactSharedPacketRewriteBypassCapacity
	UDPRecoveryMapCapacity                   = core.UDPRecoveryMapCapacity
	CompactSelfBypassSocketCapacity          = core.CompactSelfBypassSocketCapacity
	CompactTCAssignmentCapacity              = core.CompactTCAssignmentCapacity
	MaxConfigurableMapCapacity               = core.MaxConfigurableMapCapacity

	DefaultTCRoutingMark = core.DefaultTCRoutingMark
	TCPathShared         = core.TCPathShared
	TCPathDelivery       = core.TCPathDelivery

	TCLinkFramingUnsupported = core.TCLinkFramingUnsupported
	TCLinkFramingEthernet    = core.TCLinkFramingEthernet
	TCLinkFramingRawIP       = core.TCLinkFramingRawIP

	SelfBypassUserspace        = core.SelfBypassUserspace
	SelfBypassCgroupSocket     = core.SelfBypassCgroupSocket
	SelfBypassCgroupSocketAddr = core.SelfBypassCgroupSocketAddr

	KernelProbeModeAll    = core.KernelProbeModeAll
	KernelProbeModeLocal  = core.KernelProbeModeLocal
	KernelProbeModeShared = core.KernelProbeModeShared

	KernelProbeDataPlaneTC            = core.KernelProbeDataPlaneTC
	KernelProbeDataPlaneCgroup        = core.KernelProbeDataPlaneCgroup
	KernelProbeDataPlaneSocketAssign  = core.KernelProbeDataPlaneSocketAssign
	KernelProbeDataPlanePacketRewrite = core.KernelProbeDataPlanePacketRewrite

	KernelProbePass    = core.KernelProbePass
	KernelProbeWarn    = core.KernelProbeWarn
	KernelProbeFail    = core.KernelProbeFail
	KernelProbeUnknown = core.KernelProbeUnknown

	KernelProbeRequired    = core.KernelProbeRequired
	KernelProbePerformance = core.KernelProbePerformance
)

type SelfBypass struct {
	core.SelfBypassHandle
}

func NewSelfBypass() (*SelfBypass, error) {
	backend, err := core.NewSelfBypass()
	if err != nil {
		return nil, err
	}
	return &SelfBypass{SelfBypassHandle: core.NewSelfBypassHandle(backend)}, nil
}

func NewSelfBypassWithCapacity(capacity uint32) (*SelfBypass, error) {
	backend, err := core.NewSelfBypassWithCapacity(capacity)
	if err != nil {
		return nil, err
	}
	return &SelfBypass{SelfBypassHandle: core.NewSelfBypassHandle(backend)}, nil
}

func (b *SelfBypass) AttachCgroup(config SelfBypassCgroupConfig) error {
	return core.UnwrapSelfBypass(b).AttachCgroup(config)
}

func (b *SelfBypass) CgroupAttached() bool {
	return b != nil && core.UnwrapSelfBypass(b).CgroupAttached()
}

func (b *SelfBypass) Mode() SelfBypassMode {
	if b == nil {
		return SelfBypassUserspace
	}
	return core.UnwrapSelfBypass(b).Mode()
}

func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return core.UnwrapSelfBypass(nil).RegisterSocket(rawConn)
	}
	return core.UnwrapSelfBypass(b).RegisterSocket(rawConn)
}

func (b *SelfBypass) IsClosed() bool {
	return b == nil || core.UnwrapSelfBypass(b).IsClosed()
}

func (b *SelfBypass) Close() error {
	if b == nil {
		return nil
	}
	return core.UnwrapSelfBypass(b).Close()
}

type CgroupConfig struct {
	Path         string
	EnableTCP    bool
	EnableUDP    bool
	EnableIPv6   bool
	RedirectIPv4 netip.Prefix
	RedirectIPv6 netip.Prefix
	MapCapacity  CgroupMapCapacity
	UDPTimeout   time.Duration
	Policy       CompiledPolicy
	SelfBypass   *SelfBypass
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	return core.PrepareCgroupWithSelfBypass(core.CgroupConfig{
		Path:         config.Path,
		EnableTCP:    config.EnableTCP,
		EnableUDP:    config.EnableUDP,
		EnableIPv6:   config.EnableIPv6,
		RedirectIPv4: config.RedirectIPv4,
		RedirectIPv6: config.RedirectIPv6,
		MapCapacity:  config.MapCapacity,
		UDPTimeout:   config.UDPTimeout,
		Policy:       config.Policy,
	}, config.SelfBypass)
}

type ProcessTrackerConfig struct {
	EnableTCP   bool
	EnableUDP   bool
	EnableIPv6  bool
	LocalPolicy LocalPolicy
	SelfBypass  *SelfBypass
}

func AttachProcessTracker(config ProcessTrackerConfig) (*ProcessTracker, error) {
	return core.AttachProcessTrackerWithSelfBypass(core.ProcessTrackerConfig{
		EnableTCP:   config.EnableTCP,
		EnableUDP:   config.EnableUDP,
		EnableIPv6:  config.EnableIPv6,
		LocalPolicy: config.LocalPolicy,
	}, config.SelfBypass)
}

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
	SelfBypass         *SelfBypass
	TrackProcess       bool
	ICMPEchoReply      bool
	AssignmentCapacity uint32
}

type TCBackend struct {
	core.TCBackendHandle
}

func PrepareTC(config TCConfig) (*TCBackend, error) {
	backend, err := core.PrepareTCWithSelfBypass(core.TCConfig{
		ListenerPort:       config.ListenerPort,
		EnableLocal:        config.EnableLocal,
		EnableShared:       config.EnableShared,
		EnableIPv4:         config.EnableIPv4,
		EnableLocalIPv6:    config.EnableLocalIPv6,
		EnableSharedIPv6:   config.EnableSharedIPv6,
		EnableTCP:          config.EnableTCP,
		EnableUDP:          config.EnableUDP,
		DeliveryInterface:  config.DeliveryInterface,
		Policy:             config.Policy,
		RoutingMark:        config.RoutingMark,
		TrackProcess:       config.TrackProcess,
		ICMPEchoReply:      config.ICMPEchoReply,
		AssignmentCapacity: config.AssignmentCapacity,
	}, config.SelfBypass)
	if err != nil {
		return nil, err
	}
	return wrapTCBackend(backend), nil
}

func wrapTCBackend(backend *core.TCBackend) *TCBackend {
	if backend == nil {
		return nil
	}
	return &TCBackend{TCBackendHandle: core.NewTCBackendHandle(backend)}
}

func (b *TCBackend) RegisterTCPListener(ipv6 bool, fd int) error {
	return core.UnwrapTCBackend(b).RegisterTCPListener(ipv6, fd)
}

func (b *TCBackend) LookupAssignment(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, remove bool) (TCAssignment, error) {
	return core.UnwrapTCBackend(b).LookupAssignment(protocol, source, destination, interfaceIndex, remove)
}

func (b *TCBackend) Stats() (TCStats, error) {
	return core.UnwrapTCBackend(b).Stats()
}

func (b *TCBackend) SetDeliveryInterface(interfaceIndex uint32, hardwareAddress MACAddress) error {
	return core.UnwrapTCBackend(b).SetDeliveryInterface(interfaceIndex, hardwareAddress)
}

func (b *TCBackend) SetRoutingMark(mark uint32) error {
	return core.UnwrapTCBackend(b).SetRoutingMark(mark)
}

func (b *TCBackend) Enable() error { return core.UnwrapTCBackend(b).Enable() }
func (b *TCBackend) Disable() error {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return nil
	}
	return backend.Disable()
}
func (b *TCBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	return core.UnwrapTCBackend(b).UpdateHostAddresses(addresses)
}
func (b *TCBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized TC eBPF backend")
	}
	return backend.UpdateCompiledBypassCIDR(policy)
}
func (b *TCBackend) UpdateLocalCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized TC eBPF backend")
	}
	return backend.UpdateLocalCompiledBypassCIDR(policy)
}
func (b *TCBackend) UpdateSharedCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized TC eBPF backend")
	}
	return backend.UpdateSharedCompiledBypassCIDR(policy)
}
func (b *TCBackend) TCPListenerLookupMode() string {
	return core.UnwrapTCBackend(b).TCPListenerLookupMode()
}
func (b *TCBackend) RequiresRebuild() bool {
	return b != nil && core.UnwrapTCBackend(b).RequiresRebuild()
}
func (b *TCBackend) IsClosed() bool {
	return b == nil || core.UnwrapTCBackend(b).IsClosed()
}
func (b *TCBackend) ICMPEchoReplyEnabled() bool {
	return b != nil && core.UnwrapTCBackend(b).ICMPEchoReplyEnabled()
}
func (b *TCBackend) ICMPEchoReplyCount() (uint64, error) {
	return core.UnwrapTCBackend(b).ICMPEchoReplyCount()
}
func (b *TCBackend) ICMPEchoPassThroughCount() (uint64, error) {
	return core.UnwrapTCBackend(b).ICMPEchoPassThroughCount()
}
func (b *TCBackend) ICMPEchoRewriteFailureCount() (uint64, error) {
	return core.UnwrapTCBackend(b).ICMPEchoRewriteFailureCount()
}
func (b *TCBackend) Close() error {
	if b == nil {
		return nil
	}
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return nil
	}
	return backend.Close()
}

type SharedPacketRewriteBackend struct {
	core.SharedPacketRewriteBackendHandle
}

func PrepareSharedPacketRewrite(cgroupBackend *CgroupBackend, config SharedPacketRewriteConfig) (*SharedPacketRewriteBackend, error) {
	backend, err := core.PrepareSharedPacketRewrite(cgroupBackend, config)
	if err != nil {
		return nil, err
	}
	return wrapSharedPacketRewriteBackend(backend), nil
}

func wrapSharedPacketRewriteBackend(backend *core.SharedPacketRewriteBackend) *SharedPacketRewriteBackend {
	if backend == nil {
		return nil
	}
	return &SharedPacketRewriteBackend{SharedPacketRewriteBackendHandle: core.NewSharedPacketRewriteBackendHandle(backend)}
}

func (b *SharedPacketRewriteBackend) Enable() error {
	return core.UnwrapSharedPacketRewriteBackend(b).Enable()
}
func (b *SharedPacketRewriteBackend) Disable() error {
	backend := core.UnwrapSharedPacketRewriteBackend(b)
	if backend == nil {
		return nil
	}
	return backend.Disable()
}
func (b *SharedPacketRewriteBackend) LookupFlow(protocol uint8, client, tokenDestination netip.AddrPort) (OriginalDestination, *SharedPacketRewriteFlowHandle, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).LookupFlow(protocol, client, tokenDestination)
}
func (b *SharedPacketRewriteBackend) ReserveUDPReplyFlow(base *SharedPacketRewriteFlowHandle, destination netip.AddrPort, sourceMAC net.HardwareAddr) (netip.Addr, *SharedPacketRewriteFlowHandle, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).ReserveUDPReplyFlow(base, destination, sourceMAC)
}
func (b *SharedPacketRewriteBackend) ReleaseFlow(flow *SharedPacketRewriteFlowHandle) error {
	return core.UnwrapSharedPacketRewriteBackend(b).ReleaseFlow(flow)
}
func (b *SharedPacketRewriteBackend) TCPFlowWake() <-chan struct{} {
	return core.UnwrapSharedPacketRewriteBackend(b).TCPFlowWake()
}
func (b *SharedPacketRewriteBackend) NextTCPFlowReleaseDelay(now time.Time) (time.Duration, bool) {
	return core.UnwrapSharedPacketRewriteBackend(b).NextTCPFlowReleaseDelay(now)
}
func (b *SharedPacketRewriteBackend) FlushReleasedTCPFlows(now time.Time, budget uint32) (uint32, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).FlushReleasedTCPFlows(now, budget)
}
func (b *SharedPacketRewriteBackend) SweepOrphanedFlows(maxIdle time.Duration, fallbackBudget uint32) (SharedPacketRewriteSweepResult, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).SweepOrphanedFlows(maxIdle, fallbackBudget)
}
func (b *SharedPacketRewriteBackend) PurgeInterfaceFlows(interfaceIndex uint32, budget uint32) (uint32, bool, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).PurgeInterfaceFlows(interfaceIndex, budget)
}
func (b *SharedPacketRewriteBackend) MapCapacity() SharedPacketRewriteMapCapacity {
	return core.UnwrapSharedPacketRewriteBackend(b).MapCapacity()
}
func (b *SharedPacketRewriteBackend) KnownFlowUsage() MapUsage {
	return core.UnwrapSharedPacketRewriteBackend(b).KnownFlowUsage()
}
func (b *SharedPacketRewriteBackend) RequestMaintenance() {
	core.UnwrapSharedPacketRewriteBackend(b).RequestMaintenance()
}
func (b *SharedPacketRewriteBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	return core.UnwrapSharedPacketRewriteBackend(b).UpdateHostAddresses(addresses)
}
func (b *SharedPacketRewriteBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).UpdateCompiledBypassCIDR(policy)
}
func (b *SharedPacketRewriteBackend) SetBypassCIDRState(ipv4Count, ipv6Count int) error {
	return core.UnwrapSharedPacketRewriteBackend(b).SetBypassCIDRState(ipv4Count, ipv6Count)
}
func (b *SharedPacketRewriteBackend) BypassCIDRCount() (int, int) {
	return core.UnwrapSharedPacketRewriteBackend(b).BypassCIDRCount()
}
func (b *SharedPacketRewriteBackend) TokenReservationFailures() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).TokenReservationFailures()
}
func (b *SharedPacketRewriteBackend) RewriteFailures() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).RewriteFailures()
}
func (b *SharedPacketRewriteBackend) IngressPasses() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).IngressPasses()
}
func (b *SharedPacketRewriteBackend) EgressPasses() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).EgressPasses()
}
func (b *SharedPacketRewriteBackend) IngressFragmentPasses() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).IngressFragmentPasses()
}
func (b *SharedPacketRewriteBackend) EgressFragmentPasses() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).EgressFragmentPasses()
}
func (b *SharedPacketRewriteBackend) ICMPEchoReplyEnabled() bool {
	return b != nil && core.UnwrapSharedPacketRewriteBackend(b).ICMPEchoReplyEnabled()
}
func (b *SharedPacketRewriteBackend) ICMPEchoReplyCount() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).ICMPEchoReplyCount()
}
func (b *SharedPacketRewriteBackend) ICMPEchoPassThroughCount() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).ICMPEchoPassThroughCount()
}
func (b *SharedPacketRewriteBackend) ICMPEchoRewriteFailureCount() (uint64, error) {
	return core.UnwrapSharedPacketRewriteBackend(b).ICMPEchoRewriteFailureCount()
}
func (b *SharedPacketRewriteBackend) RequiresRebuild() bool {
	return b != nil && core.UnwrapSharedPacketRewriteBackend(b).RequiresRebuild()
}
func (b *SharedPacketRewriteBackend) IsClosed() bool {
	return b == nil || core.UnwrapSharedPacketRewriteBackend(b).IsClosed()
}
func (b *SharedPacketRewriteBackend) Close() error {
	if b == nil {
		return nil
	}
	backend := core.UnwrapSharedPacketRewriteBackend(b)
	if backend == nil {
		return nil
	}
	return backend.Close()
}

func CompilePolicy(config PolicyConfig) (CompiledPolicy, error) {
	return core.CompilePolicy(config)
}

func CompileBypassCIDRPolicy(prefixes []netip.Prefix) (BypassCIDRPolicy, error) {
	return core.CompileBypassCIDRPolicy(prefixes)
}

func DefaultCgroupMapCapacity() CgroupMapCapacity {
	return core.DefaultCgroupMapCapacity()
}

func CompactSharedPacketRewriteMapCapacity() SharedPacketRewriteMapCapacity {
	return core.CompactSharedPacketRewriteMapCapacity()
}

// InspectMapOccupancy performs a one-shot inspection of maps owned by
// sing-ebpf. It does not start a background scan or affect active datapaths.
func InspectMapOccupancy() MapOccupancyReport {
	return core.InspectMapOccupancy()
}

// InspectRuntimeState performs a one-shot inspection of active sing-ebpf
// programs and maps. It does not start a background scan or affect active
// data paths.
func InspectRuntimeState() RuntimeState {
	return core.InspectRuntimeState()
}

func CompactCgroupMapCapacity() CgroupMapCapacity {
	return core.CompactCgroupMapCapacity()
}

func DefaultSharedPacketRewriteMapCapacity() SharedPacketRewriteMapCapacity {
	return core.DefaultSharedPacketRewriteMapCapacity()
}

func SelectRedirectPrefix(family int, candidates []netip.Prefix, excluded []netip.Prefix) (netip.Prefix, error) {
	return core.SelectRedirectPrefix(family, candidates, excluded)
}

func ValidateRedirectPrefix(prefix netip.Prefix) error {
	return core.ValidateRedirectPrefix(prefix)
}

func NewLocalRouteSet(prefixes []netip.Prefix) (*LocalRouteSet, error) {
	return core.NewLocalRouteSet(prefixes)
}

func DetectProcessCgroup2Path() (string, error) { return core.DetectProcessCgroup2Path() }
func DetectCgroup2Root() (string, error)        { return core.DetectCgroup2Root() }

func ClassifyTCLinkFraming(encapsulation string, hardwareType int) TCLinkFraming {
	return core.ClassifyTCLinkFraming(encapsulation, hardwareType)
}

func ProbeKernel(options KernelProbeOptions) (*KernelProbeReport, error) {
	return core.ProbeKernel(options)
}

func WriteKernelProbeReport(writer io.Writer, report *KernelProbeReport) error {
	return core.WriteKernelProbeReport(writer, report)
}

func WriteKernelProbeReportJSON(writer io.Writer, report *KernelProbeReport) error {
	return core.WriteKernelProbeReportJSON(writer, report)
}
