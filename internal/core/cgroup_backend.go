//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	cgroupProgramConnect4 = iota
	cgroupProgramUDP4Sendmsg
	cgroupProgramUDP4Recvmsg
	cgroupProgramConnect6
	cgroupProgramUDP6Sendmsg
	cgroupProgramUDP6Recvmsg
	cgroupProgramSocketRelease
	cgroupProgramGetpeername4
	cgroupProgramGetpeername6
	cgroupProgramCount
)

const (
	cgroupUDPCleanupDisabled      = "disabled"
	cgroupUDPCleanupSocketRelease = "socket_release"
	cgroupUDPCleanupLRUFallback   = "lru_fallback"
	cgroupUDPCleanupInvalid       = "invalid"
)

type cgroupProgramDefinition struct {
	kernelProgramName string
	attachType        CiliumEBPF.AttachType
}

var cgroupProgramDefinitions = [cgroupProgramCount]cgroupProgramDefinition{
	{kernelProgramName: kernelProgramNameCgroupConnect4, attachType: CiliumEBPF.AttachCGroupInet4Connect},
	{kernelProgramName: kernelProgramNameCgroupSendmsg4, attachType: CiliumEBPF.AttachCGroupUDP4Sendmsg},
	{kernelProgramName: kernelProgramNameCgroupRecvmsg4, attachType: CiliumEBPF.AttachCGroupUDP4Recvmsg},
	{kernelProgramName: kernelProgramNameCgroupConnect6, attachType: CiliumEBPF.AttachCGroupInet6Connect},
	{kernelProgramName: kernelProgramNameCgroupSendmsg6, attachType: CiliumEBPF.AttachCGroupUDP6Sendmsg},
	{kernelProgramName: kernelProgramNameCgroupRecvmsg6, attachType: CiliumEBPF.AttachCGroupUDP6Recvmsg},
	{kernelProgramName: kernelProgramNameCgroupRelease, attachType: CiliumEBPF.AttachCgroupInetSockRelease},
	{kernelProgramName: kernelProgramNameCgroupGetpeername4, attachType: CiliumEBPF.AttachCgroupInet4GetPeername},
	{kernelProgramName: kernelProgramNameCgroupGetpeername6, attachType: CiliumEBPF.AttachCgroupInet6GetPeername},
}

type cgroupRuntime struct {
	cgroupFile   *os.File
	slot         *InstanceSlot
	maps         map[string]*CiliumEBPF.Map
	programs     []*CiliumEBPF.Program
	links        [cgroupProgramCount]link.Link
	attached     [cgroupProgramCount]bool
	attach_modes [cgroupProgramCount]string
	// displaced holds, per legacy attachment, the netd placeholder it
	// replaced on a single-program hook; detach puts it back.
	displaced                   [cgroupProgramCount]*displacedCgroupOwner
	control_map_fd              int
	tcp_redirect_map_fd         int
	udp_redirect_map_fd         int
	udp_recovery_map_fd         int
	udp_token_map_fd            int
	udp_token_reverse_map_fd    int
	udp_peer_map_fd             int
	udp_flow_map_fd             int
	bypass_socket_cookie_map_fd int
	uid_policy_map_fd           int
	bypass_ipv4_cidr_map_fd     int
	bypass_ipv6_cidr_map_fd     int
	host_ipv4_map_fd            int
	host_ipv6_map_fd            int
	udp_release_reader          *ringbuf.Reader
	udp_release_record          ringbuf.Record
	udp_release_observer        bool
	udp_release_fallback_reason string
	socket_release_supported    bool
	// sk_storage binds peer restoration to the kernel socket lifetime. It is
	// selected only when the optional map type and socket-release hook both
	// exist; older Android/vendor kernels retain the cookie-map fallback.
	sk_storage bool
	// getpeername_supported reports Linux 5.8+ getpeername hooks. They are
	// optional: without them a redirected socket reports its listener token
	// as the peer, as before.
	getpeername4_supported bool
	getpeername6_supported bool
	coarse_time_supported  bool
	direct_tgid            bool
	enable_tcp             bool
	enable_udp             bool
	uid_policy             bool
	uid_default_bypass     bool
	bypass_ipv4_policy     bool
	bypass_ipv6_policy     bool
	bypass_port_policy     bool
}

type CgroupBackend struct {
	access                 sync.RWMutex
	health                 backendHealth
	recovery               cgroupRecoveryStore
	udpReleaseReadAccess   sync.Mutex
	udpReplyTokenSequence  atomic.Uint64
	lookupAndDeleteMode    atomic.Int32
	udpRecoveryConsumeMode atomic.Int32
	runtime                *cgroupRuntime
	mapCapacity            CgroupMapCapacity
	tcpRedirectMapFD       int
	udpRedirectMapFD       int
	udpRecoveryMapFD       int
	udpFlowMapFD           int
	socketBypassMapFD      int
	bypassIPv4CIDRMapFD    int
	bypassIPv6CIDRMapFD    int
	hostIPv4MapFD          int
	hostIPv6MapFD          int
	bypassIPv4CIDR         []netip.Prefix
	bypassIPv6CIDR         []netip.Prefix
	hostIPv4               []netip.Prefix
	hostIPv6               []netip.Prefix
	cgroupPath             string
	redirectIPv4           netip.Prefix
	redirectIPv6           netip.Prefix
	enableIPv6             bool
	enableUDP              bool
	forceIPv4, forceIPv6   bool
	udpTimeoutSeconds      uint32
	networkGeneration      uint32
	listenerPort           uint16
	selfBypass             *SelfBypass
	selfBypassTGID         uint32
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	cgroupPath := config.Path
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	mapCapacity := config.MapCapacity
	policy := config.Policy
	var err error
	if err := validateCgroupMapCapacity(mapCapacity); err != nil {
		return nil, err
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if !redirectIPv4.Addr().Is4() {
			return nil, E.New("invalid IPv4 eBPF redirect address: ", redirectIPv4)
		}
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if !redirectIPv6.Addr().Is6() || redirectIPv6.Addr().Is4In6() {
			return nil, E.New("invalid IPv6 eBPF redirect address: ", redirectIPv6)
		}
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing eBPF redirect address")
	}
	if config.EnableIPv6 && !redirectIPv6.IsValid() {
		return nil, E.New("missing IPv6 eBPF redirect address")
	}
	if !redirectIPv4.IsValid() && !config.EnableIPv6 {
		return nil, E.New("eBPF cgroup backend has no enabled address family")
	}
	udpTimeoutSeconds := uint32(0)
	if config.EnableUDP {
		udpTimeoutSeconds, err = cgroupUDPTimeoutSeconds(config.UDPTimeout)
		if err != nil {
			return nil, err
		}
	}
	uidPolicyEntries, uidDefaultBypass := policy.uidEntries, policy.uidDefaultBypass
	if err = checkLPMTriePolicyCompatibility("UID", len(uidPolicyEntries)); err != nil {
		return nil, err
	}
	if cgroupPath == "" {
		cgroupPath, err = DetectCgroup2Root()
		if err != nil {
			return nil, err
		}
	}
	memlockErr := raiseMemlockLimit()
	if err = validateCgroup2Mount("cgroup", cgroupPath); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		return nil, eBPFOperationError("open cgroup", err)
	}
	slot, err := acquireCgroupSlot(cgroupFile)
	if err != nil {
		_ = cgroupFile.Close()
		return nil, err
	}
	closeCgroup := func() {
		_ = cgroupFile.Close()
		_ = slot.Close()
	}
	exclusive, err := lockCgroupFile(cgroupFile)
	if err != nil {
		closeCgroup()
		return nil, err
	}
	reclaimSlot := slot.Index()
	if exclusive {
		reclaimSlot = cgroupReclaimAllSlots
	} else if cgroupSharedAcrossNetworkNamespaces(cgroupFile) {
		reclaimSlot = cgroupReclaimNoSlot
	}
	if err = detachOwnedCgroupPrograms(int(cgroupFile.Fd()), reclaimSlot); err != nil {
		closeCgroup()
		return nil, eBPFOperationError("detach stale cgroup programs", err)
	}
	if exclusive {
		if err = shareCgroupLock(cgroupFile); err != nil {
			closeCgroup()
			return nil, err
		}
	}
	socketReleaseSupported := false
	skStorage := false
	coarseTimeSupported := false
	if config.EnableUDP {
		coarseTimeSupported = features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnKtimeGetCoarseNs) == nil
		socketReleaseSupported, err = probeSocketReleaseSupport(int(cgroupFile.Fd()))
		if err != nil {
			closeCgroup()
			return nil, eBPFOperationError("probe socket release attachment", err)
		}
	}
	if socketReleaseSupported &&
		features.HaveMapType(CiliumEBPF.SkStorage) == nil &&
		features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnSkStorageGet) == nil {
		skStorage = true
	}
	runtimeState := &cgroupRuntime{
		cgroupFile:               cgroupFile,
		slot:                     slot,
		maps:                     make(map[string]*CiliumEBPF.Map),
		programs:                 make([]*CiliumEBPF.Program, cgroupProgramCount),
		enable_tcp:               config.EnableTCP,
		enable_udp:               config.EnableUDP,
		uid_policy:               len(uidPolicyEntries) > 0 || uidDefaultBypass,
		uid_default_bypass:       uidDefaultBypass,
		bypass_ipv4_policy:       len(policy.localInitialBypass.ipv4) > 0,
		bypass_ipv6_policy:       len(policy.localInitialBypass.ipv6) > 0,
		bypass_port_policy:       len(policy.localBypassPortEntries) > 0,
		socket_release_supported: socketReleaseSupported,
		sk_storage:               skStorage,
		coarse_time_supported:    coarseTimeSupported,
		getpeername4_supported:   probeGetpeernameSupport(CiliumEBPF.AttachCgroupInet4GetPeername),
		getpeername6_supported:   probeGetpeernameSupport(CiliumEBPF.AttachCgroupInet6GetPeername),
	}
	if err = prepareCgroupMaps(runtimeState, mapCapacity, len(uidPolicyEntries), len(policy.localBypassPortEntries), config.SelfBypassMap, policy.localForce); err != nil {
		if runtimeState.sk_storage {
			// Map-type probes are advisory on vendor kernels. Retry with the
			// cookie-map object if SK_STORAGE creation or verifier support is
			// incomplete despite the positive feature probe.
			_ = closeMaps(runtimeState.maps)
			runtimeState.maps = make(map[string]*CiliumEBPF.Map)
			runtimeState.sk_storage = false
			err = prepareCgroupMaps(runtimeState, mapCapacity, len(uidPolicyEntries), len(policy.localBypassPortEntries), config.SelfBypassMap, policy.localForce)
		}
	}
	if err != nil {
		_ = closeMaps(runtimeState.maps)
		closeCgroup()
		if errors.Is(err, unix.EPERM) {
			err = explainBPFPermissionError(err, memlockErr)
		} else if memlockErr != nil && errors.Is(err, unix.ENOMEM) {
			err = E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	backend := &CgroupBackend{
		mapCapacity:         mapCapacity,
		runtime:             runtimeState,
		tcpRedirectMapFD:    runtimeState.tcp_redirect_map_fd,
		udpRedirectMapFD:    runtimeState.udp_redirect_map_fd,
		udpRecoveryMapFD:    runtimeState.udp_recovery_map_fd,
		udpFlowMapFD:        runtimeState.udp_flow_map_fd,
		socketBypassMapFD:   runtimeState.bypass_socket_cookie_map_fd,
		bypassIPv4CIDRMapFD: runtimeState.bypass_ipv4_cidr_map_fd,
		bypassIPv6CIDRMapFD: runtimeState.bypass_ipv6_cidr_map_fd,
		hostIPv4MapFD:       runtimeState.host_ipv4_map_fd,
		hostIPv6MapFD:       runtimeState.host_ipv6_map_fd,
		cgroupPath:          cgroupPath,
		redirectIPv4:        redirectIPv4,
		redirectIPv6:        redirectIPv6,
		forceIPv4:           len(policy.localForce.ipv4) > 0,
		forceIPv6:           len(policy.localForce.ipv6) > 0,
		enableIPv6:          config.EnableIPv6,
		enableUDP:           config.EnableUDP,
		udpTimeoutSeconds:   udpTimeoutSeconds,
		selfBypass:          config.selfBypass,
		selfBypassTGID:      config.selfBypassTGID,
		bypassIPv4CIDR:      slices.Clone(policy.localInitialBypass.ipv4),
		bypassIPv6CIDR:      slices.Clone(policy.localInitialBypass.ipv6),
	}
	runtimeState.direct_tgid = config.selfBypassTGID != 0
	if err = populateCompiledPolicyMaps(policyMapTargets{
		LocalForceIPv4:  runtimeState.maps["cgroup_force4"],
		LocalForceIPv6:  runtimeState.maps["cgroup_force6"],
		Scope:           "cgroup eBPF",
		UID:             runtimeState.maps["cgroup_uid_policy"],
		LocalPort:       runtimeState.maps["cgroup_bypass_port"],
		LocalBypassIPv4: runtimeState.maps["cgroup_bypass_ipv4"],
		LocalBypassIPv6: runtimeState.maps["cgroup_bypass_ipv6"],
	}, policy); err != nil {
		_ = backend.Close()
		return nil, err
	}
	return backend, nil
}
