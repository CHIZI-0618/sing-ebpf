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
	DNSMode                      = core.DNSMode
	UIDRange                     = core.UIDRange
	LocalPolicy                  = core.LocalPolicy
	MACAddress                   = core.MACAddress
	PortRange                    = core.PortRange
	PolicyConfig                 = core.PolicyConfig
	CompiledPolicy               = core.CompiledPolicy
	BypassCIDRPolicy             = core.BypassCIDRPolicy
	CgroupMapCapacity            = core.CgroupMapCapacity
	MapUsage                     = core.MapUsage
	SharedNetworkMapCapacities   = core.SharedNetworkMapCapacities
	OriginalDestination          = core.OriginalDestination
	CgroupBackend                = core.CgroupBackend
	SharedNetworkConfig          = core.SharedNetworkConfig
	SharedNetworkFlowHandle      = core.SharedNetworkFlowHandle
	SharedNetworkFlowSweepResult = core.SharedNetworkFlowSweepResult
	TCAssignment                 = core.TCAssignment
	TCLinkFraming                = core.TCLinkFraming
	AttachmentInfo               = core.AttachmentInfo
	TCNetworkInfo                = core.TCNetworkInfo
	SelfBypassCgroupConfig       = core.SelfBypassCgroupConfig
	SelfBypassMode               = core.SelfBypassMode
	ProcessSocketOwner           = core.ProcessSocketOwner
	ProcessTracker               = core.ProcessTracker
	LocalRouteSet                = core.LocalRouteSet
	KernelProbeMode              = core.KernelProbeMode
	KernelProbeDataPlane         = core.KernelProbeDataPlane
	KernelProbeStatus            = core.KernelProbeStatus
	KernelProbeImportance        = core.KernelProbeImportance
	KernelProbeOptions           = core.KernelProbeOptions
	KernelProbeFinding           = core.KernelProbeFinding
	KernelProbeProgram           = core.KernelProbeProgram
	KernelProbeReport            = core.KernelProbeReport
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

	TCPRedirectMapCapacity      = core.TCPRedirectMapCapacity
	UDPRedirectMapCapacity      = core.UDPRedirectMapCapacity
	UDPPeerMapCapacity          = core.UDPPeerMapCapacity
	UDPFlowMapCapacity          = core.UDPFlowMapCapacity
	SocketBypassMapCapacity     = core.SocketBypassMapCapacity
	SharedNetworkProxyCapacity  = core.SharedNetworkProxyCapacity
	SharedNetworkBypassCapacity = core.SharedNetworkBypassCapacity
	UDPRecoveryMapCapacity      = core.UDPRecoveryMapCapacity
	MaxConfigurableMapCapacity  = core.MaxConfigurableMapCapacity

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
	ListenerPort      uint16
	EnableLocal       bool
	EnableShared      bool
	EnableIPv4        bool
	EnableLocalIPv6   bool
	EnableSharedIPv6  bool
	EnableTCP         bool
	EnableUDP         bool
	DeliveryInterface uint32
	Policy            CompiledPolicy
	RoutingMark       uint32
	SelfBypass        *SelfBypass
	TrackProcess      bool
	FakeIPICMPReply   bool
}

type TCBackend struct {
	core.TCBackendHandle
}

func PrepareTC(config TCConfig) (*TCBackend, error) {
	backend, err := core.PrepareTCWithSelfBypass(core.TCConfig{
		ListenerPort:      config.ListenerPort,
		EnableLocal:       config.EnableLocal,
		EnableShared:      config.EnableShared,
		EnableIPv4:        config.EnableIPv4,
		EnableLocalIPv6:   config.EnableLocalIPv6,
		EnableSharedIPv6:  config.EnableSharedIPv6,
		EnableTCP:         config.EnableTCP,
		EnableUDP:         config.EnableUDP,
		DeliveryInterface: config.DeliveryInterface,
		Policy:            config.Policy,
		RoutingMark:       config.RoutingMark,
		TrackProcess:      config.TrackProcess,
		FakeIPICMPReply:   config.FakeIPICMPReply,
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
func (b *TCBackend) TCPListenerLookupMode() string {
	return core.UnwrapTCBackend(b).TCPListenerLookupMode()
}
func (b *TCBackend) RequiresRebuild() bool {
	return b != nil && core.UnwrapTCBackend(b).RequiresRebuild()
}
func (b *TCBackend) FakeIPICMPEnabled() bool {
	return b != nil && core.UnwrapTCBackend(b).FakeIPICMPEnabled()
}
func (b *TCBackend) FakeIPICMPReplyCount() (uint64, error) {
	return core.UnwrapTCBackend(b).FakeIPICMPReplyCount()
}
func (b *TCBackend) FakeIPICMPPassThroughCount() (uint64, error) {
	return core.UnwrapTCBackend(b).FakeIPICMPPassThroughCount()
}
func (b *TCBackend) FakeIPICMPRewriteFailureCount() (uint64, error) {
	return core.UnwrapTCBackend(b).FakeIPICMPRewriteFailureCount()
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

type SharedNetworkBackend struct {
	core.SharedNetworkBackendHandle
}

func PrepareSharedNetwork(cgroupBackend *CgroupBackend, config SharedNetworkConfig) (*SharedNetworkBackend, error) {
	backend, err := core.PrepareSharedNetwork(cgroupBackend, config)
	if err != nil {
		return nil, err
	}
	return wrapSharedNetworkBackend(backend), nil
}

func wrapSharedNetworkBackend(backend *core.SharedNetworkBackend) *SharedNetworkBackend {
	if backend == nil {
		return nil
	}
	return &SharedNetworkBackend{SharedNetworkBackendHandle: core.NewSharedNetworkBackendHandle(backend)}
}

func (b *SharedNetworkBackend) Enable() error { return core.UnwrapSharedNetworkBackend(b).Enable() }
func (b *SharedNetworkBackend) Disable() error {
	backend := core.UnwrapSharedNetworkBackend(b)
	if backend == nil {
		return nil
	}
	return backend.Disable()
}
func (b *SharedNetworkBackend) LookupFlow(protocol uint8, client, tokenDestination netip.AddrPort) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return core.UnwrapSharedNetworkBackend(b).LookupFlow(protocol, client, tokenDestination)
}
func (b *SharedNetworkBackend) ReserveUDPReplyFlow(base *SharedNetworkFlowHandle, destination netip.AddrPort, sourceMAC net.HardwareAddr) (netip.Addr, *SharedNetworkFlowHandle, error) {
	return core.UnwrapSharedNetworkBackend(b).ReserveUDPReplyFlow(base, destination, sourceMAC)
}
func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlowHandle) error {
	return core.UnwrapSharedNetworkBackend(b).ReleaseFlow(flow)
}
func (b *SharedNetworkBackend) TCPFlowWake() <-chan struct{} {
	return core.UnwrapSharedNetworkBackend(b).TCPFlowWake()
}
func (b *SharedNetworkBackend) NextTCPFlowReleaseDelay(now time.Time) (time.Duration, bool) {
	return core.UnwrapSharedNetworkBackend(b).NextTCPFlowReleaseDelay(now)
}
func (b *SharedNetworkBackend) FlushReleasedTCPFlows(now time.Time, budget uint32) (uint32, error) {
	return core.UnwrapSharedNetworkBackend(b).FlushReleasedTCPFlows(now, budget)
}
func (b *SharedNetworkBackend) SweepOrphanedFlows(maxIdle time.Duration, fallbackBudget uint32) (SharedNetworkFlowSweepResult, error) {
	return core.UnwrapSharedNetworkBackend(b).SweepOrphanedFlows(maxIdle, fallbackBudget)
}
func (b *SharedNetworkBackend) PurgeInterfaceFlows(interfaceIndex uint32, budget uint32) (uint32, bool, error) {
	return core.UnwrapSharedNetworkBackend(b).PurgeInterfaceFlows(interfaceIndex, budget)
}
func (b *SharedNetworkBackend) MapCapacity() SharedNetworkMapCapacities {
	return core.UnwrapSharedNetworkBackend(b).MapCapacity()
}
func (b *SharedNetworkBackend) KnownFlowUsage() MapUsage {
	return core.UnwrapSharedNetworkBackend(b).KnownFlowUsage()
}
func (b *SharedNetworkBackend) RequestMaintenance() {
	core.UnwrapSharedNetworkBackend(b).RequestMaintenance()
}
func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	return core.UnwrapSharedNetworkBackend(b).UpdateHostAddresses(addresses)
}
func (b *SharedNetworkBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	return core.UnwrapSharedNetworkBackend(b).UpdateCompiledBypassCIDR(policy)
}
func (b *SharedNetworkBackend) SetBypassCIDRState(ipv4Count, ipv6Count int) error {
	return core.UnwrapSharedNetworkBackend(b).SetBypassCIDRState(ipv4Count, ipv6Count)
}
func (b *SharedNetworkBackend) BypassCIDRCount() (int, int) {
	return core.UnwrapSharedNetworkBackend(b).BypassCIDRCount()
}
func (b *SharedNetworkBackend) TokenReservationFailures() (uint64, error) {
	return core.UnwrapSharedNetworkBackend(b).TokenReservationFailures()
}
func (b *SharedNetworkBackend) RewriteFailures() (uint64, error) {
	return core.UnwrapSharedNetworkBackend(b).RewriteFailures()
}
func (b *SharedNetworkBackend) FakeIPICMPEnabled() bool {
	return b != nil && core.UnwrapSharedNetworkBackend(b).FakeIPICMPEnabled()
}
func (b *SharedNetworkBackend) FakeIPICMPReplyCount() (uint64, error) {
	return core.UnwrapSharedNetworkBackend(b).FakeIPICMPReplyCount()
}
func (b *SharedNetworkBackend) FakeIPICMPPassThroughCount() (uint64, error) {
	return core.UnwrapSharedNetworkBackend(b).FakeIPICMPPassThroughCount()
}
func (b *SharedNetworkBackend) FakeIPICMPRewriteFailureCount() (uint64, error) {
	return core.UnwrapSharedNetworkBackend(b).FakeIPICMPRewriteFailureCount()
}
func (b *SharedNetworkBackend) RequiresRebuild() bool {
	return b != nil && core.UnwrapSharedNetworkBackend(b).RequiresRebuild()
}
func (b *SharedNetworkBackend) IsClosed() bool {
	return b == nil || core.UnwrapSharedNetworkBackend(b).IsClosed()
}
func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	backend := core.UnwrapSharedNetworkBackend(b)
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

func DefaultSharedNetworkMapCapacities() SharedNetworkMapCapacities {
	return core.DefaultSharedNetworkMapCapacities()
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
