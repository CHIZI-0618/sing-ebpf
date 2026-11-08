//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestRawCgroupAttachPrefersMulti(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	var options link.RawAttachProgramOptions
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		options = current
		return nil
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want one multi-program attempt", callCount)
	}
	if options.Target != 42 || options.Attach != CiliumEBPF.AttachCgroupInetSockRelease || options.Flags != unix.BPF_F_ALLOW_MULTI {
		t.Fatalf("raw attach options = %+v, want target=42 attach=socket_release flags=BPF_F_ALLOW_MULTI", options)
	}
}

func TestRawCgroupAttachMultiOnlyNeverFallsBack(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	callCount := 0
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		callCount++
		if current.Flags != unix.BPF_F_ALLOW_MULTI {
			t.Fatalf("multi-only probe used flags %#x", current.Flags)
		}
		return unix.EPERM
	}
	if err := attachProgramRawMultiOnly(42, nil, CiliumEBPF.AttachCgroupInetSockRelease); !errors.Is(err, unix.EPERM) {
		t.Fatalf("multi-only attach error = %v, want EPERM", err)
	}
	if callCount != 1 {
		t.Fatalf("multi-only attach called %d times, want one attempt", callCount)
	}
}

func TestRawCgroupAttachFallsBackToExclusiveAfterMultiCompatibilityError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		if current.Target != 42 || current.Attach != CiliumEBPF.AttachCGroupInet4Connect {
			t.Fatalf("unexpected attach options: %+v", current)
		}
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}

func TestRawCgroupAttachPreservesExistingOwner(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	originalDescribe := describeCgroupProgram
	t.Cleanup(func() {
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
		describeCgroupProgram = originalDescribe
	})
	var flags []uint32
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	}
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{Programs: []link.AttachedProgram{{ID: 1}}}, nil
	}
	describeCgroupProgram = func(CiliumEBPF.ProgramID) string { return "id=1 name=netd_conn4" }
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		t.Fatal("existing cgroup owner was replaced")
	}
	if !strings.Contains(err.Error(), "netd_conn4") {
		t.Fatalf("error = %v, want existing owner name", err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only the non-destructive multi attach", flags)
	}
}

func TestRawCgroupAttachOccupiedErrorNamesOwners(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	originalDescribe := describeCgroupProgram
	t.Cleanup(func() {
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
		describeCgroupProgram = originalDescribe
	})
	rawAttachProgram = func(current link.RawAttachProgramOptions) error {
		if current.Flags != unix.BPF_F_ALLOW_MULTI {
			t.Fatalf("occupied hook received destructive attach flags %#x", current.Flags)
		}
		return unix.EPERM
	}
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{Programs: []link.AttachedProgram{{ID: 57}}}, nil
	}
	describeCgroupProgram = func(id CiliumEBPF.ProgramID) string {
		if id != 57 {
			t.Fatalf("described program %d, want 57", id)
		}
		return "id=57 name=foreign_conn4"
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if !errors.Is(err, ErrCgroupHookOccupied) {
		t.Fatalf("error = %v, want ErrCgroupHookOccupied", err)
	}
	for _, want := range []string{"refusing to replace existing cgroup program owner", "CGroupInet4Connect", "id=57 name=foreign_conn4"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
	// The backend wraps the error; the sentinel must survive that wrapping.
	wrapped := eBPFBackendOperationError("attach eBPF cgroup programs", kernelProgramNameCgroupConnect4, err)
	if !errors.Is(wrapped, ErrCgroupHookOccupied) {
		t.Fatalf("wrapped error lost ErrCgroupHookOccupied: %v", wrapped)
	}
}

func TestRawCgroupAttachFallbackErrors(t *testing.T) {
	for _, multiErr := range []error{
		unix.EINVAL,
		unix.EPERM,
		unix.ENOTSUP,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
	} {
		t.Run(multiErr.Error(), func(t *testing.T) {
			originalRawAttachProgram := rawAttachProgram
			t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
			var flags []uint32
			rawAttachProgram = func(current link.RawAttachProgramOptions) error {
				flags = append(flags, current.Flags)
				if current.Flags == unix.BPF_F_ALLOW_MULTI {
					return multiErr
				}
				return nil
			}
			if err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
				t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
			}
		})
	}
}

func TestRawCgroupAttachDoesNotFallbackOnFatalError(t *testing.T) {
	originalRawAttachProgram := rawAttachProgram
	t.Cleanup(func() { rawAttachProgram = originalRawAttachProgram })
	wantErr := unix.EACCES
	callCount := 0
	rawAttachProgram = func(link.RawAttachProgramOptions) error {
		callCount++
		return wantErr
	}
	err := attachProgramRaw(42, nil, CiliumEBPF.AttachCGroupInet4Connect)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if callCount != 1 {
		t.Fatalf("raw attach called %d times, want no exclusive fallback", callCount)
	}
}

func TestOwnedCgroupProgramNameIncludesLegacyPrefix(t *testing.T) {
	for _, testCase := range []struct {
		name string
		want bool
	}{
		{name: "sb_ebpf_conn4", want: true},
		{name: "sing_ebpf_conn4", want: true},
		{name: "cilium_conn4", want: false},
		{name: "", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ownedCgroupProgramName(testCase.name); got != testCase.want {
				t.Fatalf("ownedCgroupProgramName(%q)=%v, want %v", testCase.name, got, testCase.want)
			}
		})
	}
}

type objectMapLayout struct {
	keySize   uint32
	valueSize uint32
}

func TestTCLocalProgramsDoNotUseTGIDHelper(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{
		"classifier/local_egress_ethernet_isolated",
		"classifier/local_egress_raw_ip_isolated",
		"classifier/local_egress_ethernet_isolated_process",
		"classifier/local_egress_raw_ip_isolated_process",
	} {
		for _, program := range spec.Programs {
			if program.SectionName != section {
				continue
			}
			for _, instruction := range program.Instructions {
				if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetCurrentPidTgid {
					t.Fatalf("section %q still uses the TGID helper", section)
				}
			}
		}
	}
}

func TestTCLocalProgramsUseSocketCookieHelper(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]bool{
		"classifier/local_egress_ethernet_isolated":         true,
		"classifier/local_egress_raw_ip_isolated":           true,
		"classifier/local_egress_ethernet_isolated_process": true,
		"classifier/local_egress_raw_ip_isolated_process":   true,
	}
	for _, program := range spec.Programs {
		expected, selected := sections[program.SectionName]
		if !selected {
			continue
		}
		found := false
		for _, instruction := range program.Instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetSocketCookie {
				found = true
				break
			}
		}
		if found != expected {
			t.Errorf("section %q socket-cookie helper=%v, want %v", program.SectionName, found, expected)
		}
		delete(sections, program.SectionName)
	}
	if len(sections) != 0 {
		t.Fatalf("missing TC sections: %v", sections)
	}
}

func TestCgroupReleaseNotificationUsesRingBufferHelper(t *testing.T) {
	spec, err := loadCgroup()
	if err != nil {
		t.Fatal(err)
	}
	foundSection := false
	for _, program := range spec.Programs {
		if program.SectionName != "cgroup/sock_release_notify" {
			continue
		}
		foundSection = true
		foundHelper := false
		for _, instruction := range program.Instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnRingbufOutput {
				foundHelper = true
				break
			}
		}
		if !foundHelper {
			t.Fatal("cgroup socket-release notification does not use ring-buffer output")
		}
	}
	if !foundSection {
		t.Fatal("missing cgroup socket-release notification section")
	}
	watch := spec.Maps["cgroup_udp_release_watch"]
	if watch == nil || watch.KeySize != 8 || watch.ValueSize != 1 {
		t.Fatalf("invalid cgroup UDP release watch map: %+v", watch)
	}
	events := spec.Maps["cgroup_udp_release_events"]
	if events == nil || events.Type != CiliumEBPF.RingBuf {
		t.Fatalf("invalid cgroup UDP release event map: %+v", events)
	}
	stats := spec.Maps["cgroup_udp_release_stats"]
	if stats == nil || stats.Type != CiliumEBPF.PerCPUArray || stats.KeySize != 4 || stats.ValueSize != 8 {
		t.Fatalf("invalid cgroup UDP release stats map: %+v", stats)
	}
}

func TestEmbeddedCgroupStorageObjectLayout(t *testing.T) {
	spec, err := loadCgroupStorage()
	if err != nil {
		t.Fatal(err)
	}
	storage := spec.Maps["cgroup_socket_peer_storage"]
	if storage == nil || storage.Type != CiliumEBPF.SkStorage || storage.ValueSize == 0 {
		t.Fatalf("invalid cgroup socket storage map: %+v", storage)
	}
	if spec.Maps["cgroup_udp_peer"] != nil || spec.Maps["cgroup_tcp_peer"] != nil {
		t.Fatal("socket-storage object still contains cookie-keyed peer maps")
	}
	foundHelper := false
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnSkStorageGet {
				foundHelper = true
				break
			}
		}
		if foundHelper {
			break
		}
	}
	if !foundHelper {
		t.Fatal("socket-storage object does not use bpf_sk_storage_get")
	}
}

func TestEmbeddedTCObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadTC, map[string]objectMapLayout{
		"tc_control":             {4, 32},
		"tc_local_force4":        {8, 1},
		"tc_local_force6":        {20, 1},
		"tc_shared_force4":       {8, 1},
		"tc_shared_force6":       {20, 1},
		"tc_listener_sockets":    {4, 4},
		"tc_assignment":          {44, 40},
		"tc_assignment_claim":    {44, 16},
		"tc_return":              {44, 40},
		"tc_return_frag":         {44, 40},
		"tc_stats":               {4, 8},
		"tc_self_sockets":        {8, 4},
		"tc_uid_policy":          {8, 1},
		"tc_local_bypass_ipv4":   {8, 1},
		"tc_local_bypass_ipv6":   {20, 1},
		"tc_shared_bypass_ipv4":  {8, 1},
		"tc_shared_bypass_ipv6":  {20, 1},
		"tc_include_source_ipv4": {8, 1},
		"tc_include_source_ipv6": {20, 1},
		"tc_exclude_source_ipv4": {8, 1},
		"tc_exclude_source_ipv6": {20, 1},
		"tc_include_source_mac":  {8, 1},
		"tc_exclude_source_mac":  {8, 1},
		"tc_host_ipv4":           {4, 1},
		"tc_host_ipv6":           {16, 1},
		"tc_local_bypass_port":   {4, 1},
		"tc_shared_bypass_port":  {4, 1},
	}, []string{
		"classifier/local_egress_ethernet_isolated",
		"classifier/local_egress_raw_ip_isolated",
		"classifier/local_egress_ethernet_isolated_process",
		"classifier/local_egress_raw_ip_isolated_process",
		"classifier/shared_ingress_ethernet_isolated",
		"classifier/shared_ingress_raw_ip_isolated",
		"classifier/isolated_delivery",
		"classifier/isolated_delivery_legacy",
		"classifier/isolated_delivery_udp",
		"classifier/isolated_return",
	})
}

func TestEmbeddedTCAssignmentIsExplicitlyOwned(t *testing.T) {
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	assignment := spec.Maps["tc_assignment"]
	if assignment == nil {
		t.Fatal("missing tc_assignment map")
	}
	if assignment.Type != CiliumEBPF.Hash {
		t.Fatalf("tc_assignment type = %s, want hash", assignment.Type)
	}
	if assignment.MaxEntries != tcAssignmentCapacity {
		t.Fatalf("tc_assignment max entries = %d, want %d", assignment.MaxEntries, tcAssignmentCapacity)
	}
	if assignment.Flags&bpfFlagNoPrealloc == 0 {
		t.Fatalf("tc_assignment flags = %#x, want BPF_F_NO_PREALLOC", assignment.Flags)
	}
}

func testEmbeddedObjectLayout(
	t *testing.T,
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]objectMapLayout,
	sections []string,
) {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range maps {
		actual := spec.Maps[name]
		if actual == nil {
			t.Errorf("missing map %q", name)
			continue
		}
		if actual.KeySize != expected.keySize || actual.ValueSize != expected.valueSize {
			t.Errorf(
				"map %q has key/value size %d/%d, want %d/%d",
				name,
				actual.KeySize,
				actual.ValueSize,
				expected.keySize,
				expected.valueSize,
			)
		}
	}
	availableSections := make(map[string]bool, len(spec.Programs))
	for _, program := range spec.Programs {
		availableSections[program.SectionName] = true
	}
	for _, section := range sections {
		if !availableSections[section] {
			t.Errorf("missing program section %q", section)
		}
	}
}

func TestKernelProgramNames(t *testing.T) {
	// Keep this list aligned with program_name.go. Besides enforcing the kernel
	// limit, global uniqueness prevents diagnostics from making two concurrently
	// loaded roles look like the same program.
	names := []string{
		kernelProgramNameCgroupConnect4,
		kernelProgramNameCgroupSendmsg4,
		kernelProgramNameCgroupRecvmsg4,
		kernelProgramNameCgroupConnect6,
		kernelProgramNameCgroupSendmsg6,
		kernelProgramNameCgroupRecvmsg6,
		kernelProgramNameCgroupRelease,
		kernelProgramNameCgroupGetpeername4,
		kernelProgramNameCgroupGetpeername6,
		kernelProgramNameTCLocalEthernet,
		kernelProgramNameTCLocalRawIP,
		kernelProgramNameTCSharedEthernet,
		kernelProgramNameTCSharedRawIP,
		kernelProgramNameTCDelivery,
		kernelProgramNameSharedIngress,
		kernelProgramNameSharedEgress,
		kernelProgramNameICMPLocalEthernet,
		kernelProgramNameICMPLocalRawIP,
		kernelProgramNameICMPSharedEthernet,
		kernelProgramNameICMPSharedRawIP,
		kernelProgramNameSelfCreate,
		kernelProgramNameSelfRelease,
		kernelProgramNameSelfConnect4,
		kernelProgramNameSelfConnect6,
		kernelProgramNameSelfSendmsg4,
		kernelProgramNameSelfSendmsg6,
		kernelProgramNameProcessConnect4,
		kernelProgramNameProcessConnect6,
		kernelProgramNameProcessSendmsg4,
		kernelProgramNameProcessSendmsg6,
		kernelProgramNameProcessRelease,
		kernelProgramNameReleaseProbe,
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if len(name) == 0 || len(name) > kernelObjectNameLimit {
			t.Fatalf("invalid kernel program name %q: length %d", name, len(name))
		}
		if _, exists := seen[name]; exists {
			t.Fatalf("duplicate kernel program name: %s", name)
		}
		seen[name] = struct{}{}
	}
}

func TestKernelMapNames(t *testing.T) {
	// These are the names assigned to maps that are visible in the kernel.
	// Object symbols may be longer, but every selected override and every
	// directly-created map must fit BPF_OBJ_NAME_LEN including its NUL byte.
	names := []string{
		"sb_cg_control", "sb_cg_tcp", "sb_cg_tcp_peer", "sb_cg_udp", "sb_cg_recover",
		"sb_cg_token", "sb_cg_token_rev", "sb_cg_peer", "sb_cg_flow", "sb_cg_sock_byp",
		"sb_cg_byp_port", "sb_cg_uid", "sb_cg_bypass4", "sb_cg_bypass6", "sb_cg_host4", "sb_cg_host6",
		"sb_cg_rel_watch", "sb_cg_rel_evt", "sb_cg_rel_stat", "sb_cg_force4", "sb_cg_force6",
		"sb_tc_ctl", "sb_tc_listen", "sb_tc_assign", "sb_tc_claim", "sb_tc_stats", "sb_tc_uid", "sb_tc_lbypass4",
		"sb_tc_lbypass6", "sb_tc_sbypass4", "sb_tc_sbypass6", "sb_tc_insrc4", "sb_tc_insrc6",
		"sb_tc_exsrc4", "sb_tc_exsrc6", "sb_tc_insmac", "sb_tc_exsmac", "sb_tc_host4", "sb_tc_host6",
		"sb_tc_lport", "sb_tc_sport", "sb_self_sockets", "sb_tc_return", "sb_tc_rfrag",
		"sb_tc_lforce4", "sb_tc_lforce6", "sb_tc_sforce4", "sb_tc_sforce6",
		"sb_sh_control", "sb_sh_stats", "sb_sh_orig", "sb_sh_bypass", "sb_sh_token", "sb_sh_host4", "sb_sh_host6",
		"sb_sh_inc4", "sb_sh_inc6", "sb_sh_exc4", "sb_sh_exc6", "sb_sh_inmac", "sb_sh_exmac", "sb_sh_port", "sb_sh_scratch",
		"sb_sh_bypass4", "sb_sh_bypass6", "sb_sh_force4", "sb_sh_force6",
		"sb_icmp_ctl", "sb_icmp_stat", "sb_icmp_lforce4", "sb_icmp_lforce6", "sb_icmp_sforce4", "sb_icmp_sforce6",
		"sb_proc_owner", "sb_proc_uid", "sb_proc_probe", "sb_lpm_probe", "sb_tcx_prio",
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if err := validateKernelObjectName(name); err != nil {
			t.Errorf("map name %q: %v", name, err)
		}
		if _, ok := seen[name]; ok {
			t.Errorf("duplicate kernel map name: %s", name)
		}
		seen[name] = struct{}{}
	}
}

func TestVerifierLogRetryMaskedError(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "rejected log buffer", err: fmt.Errorf("program p: %w", &CiliumEBPF.VerifierError{Cause: unix.EINVAL}), want: true},
		{name: "verifier rejection", err: &CiliumEBPF.VerifierError{Cause: unix.EINVAL, Log: []string{"invalid func unknown#99"}}, want: false},
		{name: "complexity limit", err: &CiliumEBPF.VerifierError{Cause: unix.E2BIG}, want: false},
		{name: "no verifier error", err: unix.EINVAL, want: false},
	} {
		if got := verifierLogRetryMaskedError(testCase.err); got != testCase.want {
			t.Errorf("%s: verifierLogRetryMaskedError = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
