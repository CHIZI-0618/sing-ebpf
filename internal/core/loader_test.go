//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"slices"
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
		"classifier/local_egress_ethernet_mark",
		"classifier/local_egress_raw_ip_mark",
		"classifier/local_egress_ethernet_process",
		"classifier/local_egress_raw_ip_process",
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
		"classifier/local_egress_ethernet_mark":    true,
		"classifier/local_egress_raw_ip_mark":      true,
		"classifier/local_egress_ethernet_process": true,
		"classifier/local_egress_raw_ip_process":   true,
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
}

func TestEmbeddedTCObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadTC, map[string]objectMapLayout{
		"tc_control":             {4, 72},
		"tc_listener_sockets":    {4, 4},
		"tc_assignment":          {44, 24},
		"tc_self_sockets":        {8, 4},
		"tc_uid_policy":          {8, 1},
		"tc_bypass_ipv4":         {8, 1},
		"tc_bypass_ipv6":         {20, 1},
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
		"classifier/local_egress_ethernet_mark",
		"classifier/local_egress_raw_ip_mark",
		"classifier/local_egress_ethernet_process",
		"classifier/local_egress_raw_ip_process",
		"classifier/shared_ingress_ethernet",
		"classifier/shared_ingress_raw_ip",
		"classifier/delivery_ingress",
	})
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
