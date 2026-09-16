//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"runtime"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

func probeSelectedObjectLoads(report *KernelProbeReport, plan kernelProbePlan) {
	if plan.needsSocketAssignment() {
		detail, err := loadTCProbeObject(plan)
		reportObjectLoadResult(report, "tc", "selected TC eBPF object", detail, err)
	}
	if plan.localCgroup {
		detail, err := loadCgroupProbeObject(plan)
		reportObjectLoadResult(report, "local", "selected cgroup eBPF object", detail, err)
	}
	if plan.needProcessTracking {
		detail, err := loadProcessTrackerProbeObject(plan)
		reportObjectLoadResult(report, "local", "selected process-tracking eBPF objects", detail, err)
	}
	if plan.sharedPacketRewrite {
		detail, err := loadSharedNetworkProbeObject(plan)
		reportObjectLoadResult(report, "shared", "selected packet-rewrite eBPF object", detail, err)
	}
	if plan.icmpEchoReply {
		detail, err := loadICMPEchoReplyProbeObject(plan)
		reportObjectLoadResult(report, "icmp_echo_reply", "selected ForceIntercept ICMP eBPF object", detail, err)
	}
}

func reportObjectLoadResult(report *KernelProbeReport, scope string, feature string, detail string, err error) {
	status := classifyKernelProbeError(err)
	if err != nil {
		detail += " Load failed: " + shortProbeError(err)
	}
	report.Add(status, scope, KernelProbeRequired, feature, detail)
}

func loadTCProbeObject(plan kernelProbePlan) (string, error) {
	config := TCConfig{
		ListenerPort:      1,
		EnableLocal:       plan.localTC,
		EnableShared:      plan.sharedSocketAssign,
		EnableIPv4:        true,
		EnableLocalIPv6:   plan.localTC && plan.enableIPv6,
		EnableSharedIPv6:  plan.sharedSocketAssign && plan.enableIPv6,
		EnableTCP:         plan.enableTCP,
		EnableUDP:         plan.enableUDP,
		DeliveryInterface: 1,
		RoutingMark:       DefaultTCRoutingMark,
	}
	if runtime.GOOS == "android" {
		config.AssignmentCapacity = CompactTCAssignmentCapacity
	}
	backend, err := PrepareTC(config)
	if err != nil {
		return "Loads the generated TC programs and their real map specifications without attaching a classifier.", err
	}
	detail := "Loaded the generated TC programs and their real map specifications without attaching a classifier."
	if plan.enableTCP {
		if backend.tcpListenerMap {
			detail += " The preferred SOCKMAP TCP path loaded."
		} else {
			detail += " The kernel selected the legacy direct-listener TCP fallback."
		}
	}
	return detail, backend.Close()
}

func loadCgroupProbeObject(plan kernelProbePlan) (string, error) {
	var selfBypass *SelfBypass
	var err error
	if runtime.GOOS == "android" {
		selfBypass, err = NewSelfBypassWithCapacity(CompactSelfBypassSocketCapacity)
	} else {
		selfBypass, err = NewSelfBypass()
	}
	if err != nil {
		return "Loads the generated cgroup programs without attaching cgroup hooks.", err
	}
	runtimeState := &cgroupRuntime{
		maps:                     make(map[string]*CiliumEBPF.Map),
		programs:                 make([]*CiliumEBPF.Program, cgroupProgramCount),
		enable_tcp:               plan.enableTCP,
		enable_udp:               plan.enableUDP,
		coarse_time_supported:    plan.enableUDP && features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnKtimeGetCoarseNs) == nil,
		socket_storage_supported: plan.enableUDP && probeCgroupSocketStorageSupport(),
	}
	backend := &CgroupBackend{
		runtime:      runtimeState,
		redirectIPv4: netip.MustParsePrefix("127.0.0.0/8"),
		enableIPv6:   plan.enableIPv6,
	}
	if plan.enableIPv6 {
		backend.redirectIPv6 = netip.MustParsePrefix("fd00::/64")
	}
	mapCapacity := DefaultCgroupMapCapacity()
	if runtime.GOOS == "android" {
		mapCapacity = CompactCgroupMapCapacity()
	}
	if err = prepareCgroupMaps(runtimeState, mapCapacity, 0, 0, selfBypass.Map()); err == nil {
		runtimeState.programs, err = backend.loadCgroupObjectPrograms()
	}
	detail := "Loaded the generated cgroup programs and their real map specifications without attaching cgroup hooks."
	if err == nil {
		if runtimeState.coarse_time_supported {
			detail += " The coarse-time UDP variant loaded."
		}
		if runtimeState.socket_storage_supported {
			detail += " The socket-storage UDP variant loaded."
		}
	}
	return detail, errors.Join(err, backend.Close(), selfBypass.Close())
}

func loadProcessTrackerProbeObject(plan kernelProbePlan) (string, error) {
	owners, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_proc_owner_probe",
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: processSocketOwnerMapCapacity(runtime.GOOS),
	})
	if err != nil {
		return "Loads the process-tracking hooks without attaching them.", err
	}
	defer owners.Close()
	config := ProcessTrackerConfig{
		EnableTCP:  plan.enableTCP,
		EnableUDP:  plan.enableUDP,
		EnableIPv6: plan.enableIPv6,
	}
	var programs []*CiliumEBPF.Program
	closePrograms := func() error {
		var closeErr error
		for _, program := range programs {
			closeErr = errors.Join(closeErr, program.Close())
		}
		return closeErr
	}
	for _, hook := range processTrackerHooks(config) {
		program, loadErr := newProcessTrackerProgram(hook, owners.FD(), -1, -1, false)
		if loadErr != nil {
			return "Loads the process-tracking hooks without attaching them.", errors.Join(loadErr, closePrograms())
		}
		programs = append(programs, program)
	}
	release, loadErr := newProcessTrackerReleaseProgram(owners.FD())
	if loadErr != nil {
		return "Loads the process-tracking hooks without attaching them.", errors.Join(loadErr, closePrograms())
	}
	programs = append(programs, release)
	return "Loaded the selected process-tracking and socket-release hooks without attaching them.", closePrograms()
}

func loadSharedNetworkProbeObject(plan kernelProbePlan) (string, error) {
	config := SharedPacketRewriteConfig{
		ListenerPort: 1,
		EnableTCP:    plan.enableTCP,
		EnableUDP:    plan.enableUDP,
		RedirectIPv4: netip.MustParsePrefix("127.0.0.0/8"),
		MapCapacity:  DefaultSharedPacketRewriteMapCapacity(),
		UDPTimeout:   5 * time.Minute,
	}
	if runtime.GOOS == "android" {
		config.MapCapacity = CompactSharedPacketRewriteMapCapacity()
	}
	if plan.enableIPv6 {
		config.RedirectIPv6 = netip.MustParsePrefix("fd00::/64")
	}
	backend, err := PrepareSharedPacketRewrite(nil, config)
	if err != nil {
		return "Loads the generated shared packet-rewrite programs and their real map specifications without attaching a classifier.", err
	}
	return "Loaded the generated shared packet-rewrite programs and their real map specifications without attaching a classifier.", backend.Close()
}

func loadICMPEchoReplyProbeObject(plan kernelProbePlan) (string, error) {
	backend, err := PrepareICMPEchoReply(
		true,
		plan.localTC && plan.enableIPv6,
		(plan.sharedSocketAssign || plan.sharedPacketRewrite) && plan.enableIPv6,
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fc00::/18"),
	)
	if err != nil {
		return "Loads the generated ForceIntercept ICMP programs without attaching a classifier.", err
	}
	return "Loaded the generated ForceIntercept ICMP programs without attaching a classifier.", backend.Close()
}
