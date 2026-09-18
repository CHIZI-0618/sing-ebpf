//go:build with_ebpf && (linux || android)

package core

// Linux stores BPF program names in BPF_OBJ_NAME_LEN bytes, including the
// terminating NUL, so every kernel-visible name below must fit in 15 bytes.
// The comments preserve the unabbreviated role shown by the shorter name in
// diagnostics such as bpftool and sing-box's eBPF runtime status.
const (
	// sb_ebpf_conn4: local cgroup IPv4 TCP/UDP connect redirection.
	kernelProgramNameCgroupConnect4 = "sb_ebpf_conn4"
	// sb_ebpf_udp4: local cgroup IPv4 UDP sendmsg redirection.
	kernelProgramNameCgroupSendmsg4 = "sb_ebpf_udp4"
	// sb_ebpf_urcv4: local cgroup IPv4 UDP recvmsg destination restoration.
	kernelProgramNameCgroupRecvmsg4 = "sb_ebpf_urcv4"
	// sb_ebpf_conn6: local cgroup IPv6 TCP/UDP connect redirection.
	kernelProgramNameCgroupConnect6 = "sb_ebpf_conn6"
	// sb_ebpf_udp6: local cgroup IPv6 UDP sendmsg redirection.
	kernelProgramNameCgroupSendmsg6 = "sb_ebpf_udp6"
	// sb_ebpf_urcv6: local cgroup IPv6 UDP recvmsg destination restoration.
	kernelProgramNameCgroupRecvmsg6 = "sb_ebpf_urcv6"
	// sb_ebpf_rel: local cgroup socket-release cleanup.
	kernelProgramNameCgroupRelease = "sb_ebpf_rel"

	// sb_tc_local_l2: local TC egress interception for Ethernet frames.
	kernelProgramNameTCLocalEthernet = "sb_tc_local_l2"
	// sb_tc_local_l3: local TC egress interception for raw IP packets.
	kernelProgramNameTCLocalRawIP = "sb_tc_local_l3"
	// sb_tc_share_l2: shared-network TC ingress interception for Ethernet frames.
	kernelProgramNameTCSharedEthernet = "sb_tc_share_l2"
	// sb_tc_share_l3: shared-network TC ingress interception for raw IP packets.
	kernelProgramNameTCSharedRawIP = "sb_tc_share_l3"
	// sb_tc_deliver: TC ingress delivery to the local transparent listener.
	kernelProgramNameTCDelivery = "sb_tc_deliver"

	// sb_share_in: shared-network packet-rewrite ingress path.
	kernelProgramNameSharedIngress = "sb_share_in"
	// sb_share_out: shared-network packet-rewrite egress reply path.
	kernelProgramNameSharedEgress = "sb_share_out"

	// sb_icmp_lcl_e: local ICMP echo reply for Ethernet frames.
	kernelProgramNameICMPLocalEthernet = "sb_icmp_lcl_e"
	// sb_icmp_lcl_r: local ICMP echo reply for raw IP packets.
	kernelProgramNameICMPLocalRawIP = "sb_icmp_lcl_r"
	// sb_icmp_shr_e: shared-network ICMP echo reply for Ethernet frames.
	kernelProgramNameICMPSharedEthernet = "sb_icmp_shr_e"
	// sb_icmp_shr_r: shared-network ICMP echo reply for raw IP packets.
	kernelProgramNameICMPSharedRawIP = "sb_icmp_shr_r"

	// sb_self_create: self-bypass socket-create tracking.
	kernelProgramNameSelfCreate = "sb_self_create"
	// sb_self_release: self-bypass socket-release cleanup.
	kernelProgramNameSelfRelease = "sb_self_release"
	// sb_self_conn4: self-bypass IPv4 TCP/UDP connect tracking.
	kernelProgramNameSelfConnect4 = "sb_self_conn4"
	// sb_self_conn6: self-bypass IPv6 TCP/UDP connect tracking.
	kernelProgramNameSelfConnect6 = "sb_self_conn6"
	// sb_self_send4: self-bypass IPv4 UDP sendmsg tracking.
	kernelProgramNameSelfSendmsg4 = "sb_self_send4"
	// sb_self_send6: self-bypass IPv6 UDP sendmsg tracking.
	kernelProgramNameSelfSendmsg6 = "sb_self_send6"

	// sb_proc_conn4: process-owner tracking for IPv4 TCP/UDP connect.
	kernelProgramNameProcessConnect4 = "sb_proc_conn4"
	// sb_proc_conn6: process-owner tracking for IPv6 TCP/UDP connect.
	kernelProgramNameProcessConnect6 = "sb_proc_conn6"
	// sb_proc_send4: process-owner tracking for IPv4 UDP sendmsg.
	kernelProgramNameProcessSendmsg4 = "sb_proc_send4"
	// sb_proc_send6: process-owner tracking for IPv6 UDP sendmsg.
	kernelProgramNameProcessSendmsg6 = "sb_proc_send6"
	// sb_proc_release: process-owner socket-release cleanup.
	kernelProgramNameProcessRelease = "sb_proc_release"

	// sb_rel_probe: one-shot cgroup socket-release capability probe.
	kernelProgramNameReleaseProbe = "sb_rel_probe"
)
