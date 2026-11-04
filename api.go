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
	Decision                       = core.Decision
	ActionPolicy                   = core.ActionPolicy
	ActionScope                    = core.ActionScope
	CIDRDecision                   = core.CIDRDecision
	PortDecision                   = core.PortDecision
	UIDDecision                    = core.UIDDecision
	MACDecision                    = core.MACDecision
	MACAddress                     = core.MACAddress
	CompiledPolicy                 = core.CompiledPolicy
	CgroupMapCapacity              = core.CgroupMapCapacity
	MapUsage                       = core.MapUsage
	SharedPacketRewriteMapCapacity = core.SharedPacketRewriteMapCapacity
	OriginalDestination            = core.OriginalDestination
	CgroupBackend                  = core.CgroupBackend
	CgroupUDPStat                  = core.CgroupUDPStat
	SharedPacketRewriteConfig      = core.SharedPacketRewriteConfig
	SharedPacketRewriteFlowHandle  = core.SharedPacketRewriteFlowHandle
	SharedPacketRewriteSweepResult = core.SharedPacketRewriteSweepResult
	TCAssignment                   = core.TCAssignment
	TCReturnHandle                 = core.TCReturnHandle
	TCAssignmentSweepResult        = core.TCAssignmentSweepResult
	TCStats                        = core.TCStats
	TCLinkFraming                  = core.TCLinkFraming
	AttachmentInfo                 = core.AttachmentInfo
	TCNetworkInfo                  = core.TCNetworkInfo
	TCDiagnostics                  = core.TCDiagnostics
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
	RuntimeResources               = core.RuntimeResources
	MapCategory                    = core.MapCategory
	MapOccupancy                   = core.MapOccupancy
	MapOccupancyReport             = core.MapOccupancyReport
	UDPStateDiagnostics            = core.UDPStateDiagnostics
	UDPReleaseEvent                = core.UDPReleaseEvent
	UDPRecoverySweepResult         = core.UDPRecoverySweepResult
)

const (
	CgroupUDPStatReleaseNotificationDrops = core.CgroupUDPStatReleaseNotificationDrops
	CgroupUDPStatTCPRedirectFailure       = core.CgroupUDPStatTCPRedirectFailure
	CgroupUDPStatUDPRedirectFailure       = core.CgroupUDPStatUDPRedirectFailure
	CgroupUDPStatUDPTokenFailure          = core.CgroupUDPStatUDPTokenFailure
	CgroupUDPStatUDPTokenReverseFailure   = core.CgroupUDPStatUDPTokenReverseFailure
	CgroupUDPStatUDPPeerFailure           = core.CgroupUDPStatUDPPeerFailure
	CgroupUDPStatTCPPeerFailure           = core.CgroupUDPStatTCPPeerFailure
	CgroupUDPStatUDPRecoveryFailure       = core.CgroupUDPStatUDPRecoveryFailure
)

const (
	DecisionPass      = core.DecisionPass
	DecisionIntercept = core.DecisionIntercept

	ProtocolTCP = core.ProtocolTCP
	ProtocolUDP = core.ProtocolUDP

	SocketMetadataSelfBypass      = core.SocketMetadataSelfBypass
	SocketMetadataPolicyBypass    = core.SocketMetadataPolicyBypass
	SocketMetadataPolicyIntercept = core.SocketMetadataPolicyIntercept

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
	MapCategoryRuntime                       = core.MapCategoryRuntime
	MapCategoryConfiguredPolicy              = core.MapCategoryConfiguredPolicy

	DefaultTCRoutingMark = core.DefaultTCRoutingMark
	TCPathShared         = core.TCPathShared
	TCPathDelivery       = core.TCPathDelivery

	TCLinkFramingUnsupported = core.TCLinkFramingUnsupported
	TCLinkFramingEthernet    = core.TCLinkFramingEthernet
	TCLinkFramingRawIP       = core.TCLinkFramingRawIP

	SelfBypassUserspace        = core.SelfBypassUserspace
	SelfBypassCgroupSocket     = core.SelfBypassCgroupSocket
	SelfBypassCgroupSocketAddr = core.SelfBypassCgroupSocketAddr
	SelfBypassUserspaceRelease = core.SelfBypassUserspaceRelease

	KernelProbeModeAll    = core.KernelProbeModeAll
	KernelProbeModeLocal  = core.KernelProbeModeLocal
	KernelProbeModeShared = core.KernelProbeModeShared

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

// ErrCgroupHookOccupied is matched with errors.Is when a cgroup attachment is
// refused because the hook already holds a program in single-program mode.
// The error text names the programs currently attached to that hook and why
// the owner was kept. A pass-through owner, such as the placeholder Android
// 15+ netd keeps on the root socket-address hooks, is not refused: it is
// replaced for the backend's lifetime and restored on detach.
var ErrCgroupHookOccupied = core.ErrCgroupHookOccupied

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

func (b *SelfBypass) CleanupMode() string {
	if b == nil {
		return SelfBypassUserspace.CleanupMode()
	}
	return core.UnwrapSelfBypass(b).Mode().CleanupMode()
}

func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return core.UnwrapSelfBypass(nil).RegisterSocket(rawConn)
	}
	return core.UnwrapSelfBypass(b).RegisterSocket(rawConn)
}

func (b *SelfBypass) UnregisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	return core.UnwrapSelfBypass(b).UnregisterSocket(rawConn)
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
	EnableTCP    bool
	EnableUDP    bool
	EnableIPv6   bool
	UIDDecisions []UIDDecision
	Default      Decision
	SelfBypass   *SelfBypass
}

func AttachProcessTracker(config ProcessTrackerConfig) (*ProcessTracker, error) {
	return core.AttachProcessTrackerWithSelfBypass(core.ProcessTrackerConfig{
		EnableTCP:    config.EnableTCP,
		EnableUDP:    config.EnableUDP,
		EnableIPv6:   config.EnableIPv6,
		UIDDecisions: config.UIDDecisions,
		Default:      config.Default,
	}, config.SelfBypass)
}

type TCConfig struct {
	// TCP and UDP preserve their tuples in a required private listener namespace.
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

func (b *TCBackend) AcquireReturnRoute(protocol uint8, source, destination netip.AddrPort) (TCReturnHandle, error) {
	return core.UnwrapTCBackend(b).AcquireReturnRoute(protocol, source, destination)
}

func (b *TCBackend) AcquireReplyRoute(original TCReturnHandle, source netip.AddrPort) (TCReturnHandle, error) {
	return core.UnwrapTCBackend(b).AcquireReplyRoute(original, source)
}

func (b *TCBackend) ReleaseReturnRoute(handle TCReturnHandle) {
	core.UnwrapTCBackend(b).ReleaseReturnRoute(handle)
}

func (b *TCBackend) RemoveAssignmentIfMatch(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, expected TCAssignment) (bool, error) {
	return core.UnwrapTCBackend(b).RemoveAssignmentIfMatch(protocol, source, destination, interfaceIndex, expected)
}

func (b *TCBackend) SweepAssignments(maxIdle time.Duration, fallbackBudget uint32) (TCAssignmentSweepResult, error) {
	return core.UnwrapTCBackend(b).SweepAssignments(maxIdle, fallbackBudget)
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

// UpdateLocalDestinationDecisions applies final destination actions to the
// local TC path. The backend accepts only pass entries for this mutable map;
// intercept decisions remain part of the immutable startup policy.
func (b *TCBackend) UpdateLocalDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized TC eBPF backend")
	}
	return backend.UpdateLocalDestinationDecisions(decisions)
}

// UpdateSharedDestinationDecisions applies final destination actions to the
// shared TC path.
func (b *TCBackend) UpdateSharedDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	backend := core.UnwrapTCBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized TC eBPF backend")
	}
	return backend.UpdateSharedDestinationDecisions(decisions)
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

func PrepareSharedPacketRewrite(config SharedPacketRewriteConfig) (*SharedPacketRewriteBackend, error) {
	backend, err := core.PrepareSharedPacketRewrite(config)
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

// UpdateDestinationDecisions applies final destination actions to the shared
// packet-rewrite path.
func (b *SharedPacketRewriteBackend) UpdateDestinationDecisions(decisions []CIDRDecision) (bool, error) {
	backend := core.UnwrapSharedPacketRewriteBackend(b)
	if backend == nil {
		return false, errors.New("uninitialized shared packet-rewrite eBPF backend")
	}
	return backend.UpdateDestinationDecisions(decisions)
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

// CompileActionPolicy accepts only final pass/intercept rules. Configuration
// semantics such as DNS, FakeIP and rule-sets must be compiled by the caller.
func CompileActionPolicy(config ActionPolicy) (CompiledPolicy, error) {
	return core.CompileActionPolicy(config)
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
func (b *TCBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return core.UnwrapTCBackend(b).RuntimeResources()
}
func (b *SharedPacketRewriteBackend) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return core.UnwrapSharedPacketRewriteBackend(b).RuntimeResources()
}
func (b *SelfBypass) RuntimeResources() RuntimeResources {
	if b == nil {
		return RuntimeResources{}
	}
	return core.UnwrapSelfBypass(b).RuntimeResources()
}

// InspectRuntimeResources inspects only the IDs supplied by resource owners.
func InspectRuntimeResources(owners ...RuntimeResources) RuntimeState {
	return core.InspectRuntimeResources(owners...)
}
