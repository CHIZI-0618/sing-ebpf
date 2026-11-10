//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestCgroupProgramLinkMechanism(t *testing.T) {
	if got := cgroupProgramLinkMechanism(&legacyCgroupProgramLink{}); got != "legacy_attach" {
		t.Fatalf("legacy attachment mechanism = %q, want legacy_attach", got)
	}
	if got := cgroupProgramLinkMechanism(&retryableTestCgroupProgramLink{}); got != "bpf_link" {
		t.Fatalf("link attachment mechanism = %q, want bpf_link", got)
	}
}

func TestLegacyCgroupProgramLinkRetainsTargetAfterDetachFailure(t *testing.T) {
	cgroupFile, err := os.Create(filepath.Join(t.TempDir(), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	programLink := &legacyCgroupProgramLink{
		cgroupFile: cgroupFile,
		detachProgram: func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error {
			attempts++
			if attempts == 1 {
				return unix.EBUSY
			}
			return nil
		},
	}
	if err = programLink.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if programLink.IsClosed() {
		t.Fatal("legacy cgroup target was discarded after a failed detach")
	}
	if _, err = cgroupFile.Stat(); err != nil {
		t.Fatalf("legacy cgroup target was closed after a failed detach: %v", err)
	}
	if err = programLink.Close(); err != nil {
		t.Fatalf("retry legacy cgroup detach: %v", err)
	}
	if !programLink.IsClosed() {
		t.Fatal("legacy cgroup target remained open after a successful detach")
	}
}

type retryableTestCgroupProgramLink struct {
	failures int
	closed   bool
}

func (l *retryableTestCgroupProgramLink) Close() error {
	if l.closed {
		return nil
	}
	if l.failures > 0 {
		l.failures--
		return unix.EBUSY
	}
	l.closed = true
	return nil
}

func (l *retryableTestCgroupProgramLink) IsClosed() bool { return l.closed }

func replaceCgroupAttachOperations(
	t *testing.T,
	linkErr error,
	rawAttach func(link.RawAttachProgramOptions) error,
) {
	t.Helper()
	originalAttachRawLink := attachRawLink
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	t.Cleanup(func() {
		attachRawLink = originalAttachRawLink
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
	})
	attachRawLink = func(link.RawLinkOptions) (*link.RawLink, error) {
		return nil, linkErr
	}
	rawAttachProgram = rawAttach
	// An empty hook: the only state in which the exclusive fallback would
	// otherwise be attempted.
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{}, nil
	}
}

// The process tracker shares the cgroup v2 root with the interception
// backend. If it could fall back to an unflagged attach, the root hook would
// enter single-program mode and the kernel would then reject the backend's
// own attachment with EPERM, which surfaced as "refusing to replace existing
// cgroup program owner" for sb_ebpf_conn4.
func TestSharedCgroupAttachNeverUsesExclusiveFallback(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EPERM, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		_ = programLink.Close()
		t.Fatal("shared cgroup attach succeeded through an exclusive attachment")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("shared cgroup attach error = %v, want EPERM", err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestSharedCgroupAttachUsesLegacyMulti(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink, loaded := programLink.(*legacyCgroupProgramLink)
	if !loaded {
		t.Fatalf("link type = %T, want legacy cgroup link", programLink)
	}
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestExclusiveCgroupAttachKeepsLegacyFallbackOnEmptyHook(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EINVAL
		}
		return nil
	})
	programLink, err := attachCgroupProgram(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink := programLink.(*legacyCgroupProgramLink)
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}

func TestReclaimableCgroupProgram(t *testing.T) {
	const exclusive = cgroupReclaimAllSlots
	for _, testCase := range []struct {
		name     string
		slot     int
		flags    uint32
		count    int
		reclaim  bool
		scenario string
	}{
		{kernelProgramNameCgroupConnect4, exclusive, unix.BPF_F_ALLOW_MULTI, 2, true, "stale backend program in multi mode"},
		{kernelProgramNameCgroupConnect4, exclusive, 0, 1, true, "stale backend program in exclusive mode"},
		{kernelProgramNameCgroupConnect4 + "_3", exclusive, unix.BPF_F_ALLOW_MULTI, 2, true, "stale program of another slot while no backend is alive"},
		{kernelProgramNameCgroupConnect4, 0, unix.BPF_F_ALLOW_MULTI, 2, true, "stale program of the held slot 0"},
		{kernelProgramNameCgroupRecvmsg6 + "_f", 15, unix.BPF_F_ALLOW_MULTI, 2, true, "stale program of the held slot 15"},
		{kernelProgramNameCgroupConnect4 + "_3", 0, unix.BPF_F_ALLOW_MULTI, 2, false, "program of a live backend in slot 3"},
		{kernelProgramNameCgroupConnect4, 3, unix.BPF_F_ALLOW_MULTI, 2, false, "program of a live backend in slot 0"},
		{kernelProgramNameCgroupConnect4 + "_x", 3, unix.BPF_F_ALLOW_MULTI, 2, false, "unknown suffix"},
		{kernelProgramNameCgroupConnect4, cgroupReclaimNoSlot, unix.BPF_F_ALLOW_MULTI, 2, false, "slot numbers not unique across network namespaces"},
		{"sb_ebpf_unknown", cgroupReclaimNoSlot, unix.BPF_F_ALLOW_MULTI, 2, false, "unknown name, no slot reclaim"},
		{"sing_ebpf_conn4", exclusive, 0, 1, true, "stale program of an older release while no backend is alive"},
		{"sing_ebpf_conn4", 0, unix.BPF_F_ALLOW_MULTI, 2, true, "stale program of an older single-instance release in slot 0"},
		{"sing_ebpf_conn4", 3, unix.BPF_F_ALLOW_MULTI, 2, false, "older release's program belongs to slot 0, not this one"},
		{"sing_ebpf_conn4", cgroupReclaimNoSlot, unix.BPF_F_ALLOW_MULTI, 2, false, "older release's program, no slot reclaim"},
		{kernelProgramNameHookPlaceholder, exclusive, 0, 1, false, "pass-through handed back to netd"},
		{kernelProgramNameProcessConnect4, cgroupReclaimNoSlot, 0, 1, true, "stale exclusive tracker still blocks the hook"},
		{kernelProgramNameProcessConnect4, exclusive, 0, 1, true, "stale exclusive tracker blocks the hook"},
		{kernelProgramNameProcessConnect4, 2, 0, 1, true, "stale exclusive tracker blocks the hook beside live backends"},
		{kernelProgramNameProcessConnect4, exclusive, unix.BPF_F_ALLOW_OVERRIDE, 1, true, "stale override tracker blocks the hook"},
		{kernelProgramNameProcessConnect4, exclusive, unix.BPF_F_ALLOW_MULTI, 1, false, "live multi tracker of this or another process"},
		{kernelProgramNameProcessRelease, exclusive, unix.BPF_F_ALLOW_MULTI, 3, false, "multi tracker beside other owners"},
		{kernelProgramNameSelfConnect4, exclusive, 0, 1, false, "self-bypass belongs to a process cgroup"},
		{"inet4_connect", exclusive, 0, 1, false, "foreign owner"},
		{"", exclusive, 0, 1, false, "unnamed foreign owner"},
	} {
		if got := reclaimableCgroupProgram(testCase.name, testCase.slot, testCase.flags, testCase.count); got != testCase.reclaim {
			t.Errorf("%s: reclaimable(%q, slot %d, %#x, %d) = %v, want %v",
				testCase.scenario, testCase.name, testCase.slot, testCase.flags, testCase.count, got, testCase.reclaim)
		}
	}
}

// TestCgroupKernelProgramNamesIdentifyTheirSlot covers the names reclaim relies
// on: every slot's name fits the kernel's limit and reads back as that slot.
func TestCgroupKernelProgramNamesIdentifyTheirSlot(t *testing.T) {
	for _, definition := range cgroupProgramDefinitions {
		for slot := range MaxInstanceSlots {
			name := cgroupKernelProgramName(definition.kernelProgramName, slot)
			if len(name) > kernelObjectNameLimit {
				t.Errorf("slot %d name %q exceeds the kernel's 15-byte limit", slot, name)
			}
			if got := cgroupProgramSlot(name); got != slot {
				t.Errorf("cgroupProgramSlot(%q) = %d, want %d", name, got, slot)
			}
		}
	}
	if got := cgroupProgramSlot(kernelProgramNameProcessConnect4); got != -1 {
		t.Errorf("a process tracker name reads as slot %d", got)
	}
}

func TestCgroupProgramNamePrefixes(t *testing.T) {
	for _, definition := range cgroupProgramDefinitions {
		if !strings.HasPrefix(definition.kernelProgramName, kernelProgramPrefixCgroup) {
			t.Errorf("interception program %q lacks prefix %q", definition.kernelProgramName, kernelProgramPrefixCgroup)
		}
	}
	for _, name := range []string{
		kernelProgramNameProcessConnect4,
		kernelProgramNameProcessConnect6,
		kernelProgramNameProcessSendmsg4,
		kernelProgramNameProcessSendmsg6,
		kernelProgramNameProcessRelease,
	} {
		if !strings.HasPrefix(name, kernelProgramPrefixProcessTracker) {
			t.Errorf("process tracker program %q lacks prefix %q", name, kernelProgramPrefixProcessTracker)
		}
		if strings.HasPrefix(name, kernelProgramPrefixCgroup) {
			t.Errorf("process tracker program %q would be reclaimed as an interception program", name)
		}
	}
}

func TestForeignNetworkNamespaceLockHolder(t *testing.T) {
	const listing = `1: FLOCK  ADVISORY  READ  100 00:1d:42 0 EOF
1: -> FLOCK  ADVISORY  WRITE 300 00:1d:42 0 EOF
2: FLOCK  ADVISORY  READ  200 00:1d:43 0 EOF
3: POSIX  ADVISORY  WRITE 400 00:1d:42 0 EOF
4: FLOCK  ADVISORY  READ  500 00:1d:42 0 EOF
`
	namespaces := map[int]string{100: "net:[1]", 200: "net:[2]", 300: "net:[1]", 400: "net:[2]"}
	lookup := func(pid int) (string, error) {
		namespace, found := namespaces[pid]
		if !found {
			return "", os.ErrNotExist
		}
		return namespace, nil
	}
	if foreignNetworkNamespaceLockHolder(strings.NewReader(listing), "00:1d:42", 1, "net:[1]", lookup) {
		t.Fatal("holders in the own network namespace, a POSIX lock and an exited holder counted as foreign")
	}
	if !foreignNetworkNamespaceLockHolder(strings.NewReader(listing), "00:1d:43", 1, "net:[1]", lookup) {
		t.Fatal("a holder in another network namespace was missed")
	}
	if foreignNetworkNamespaceLockHolder(strings.NewReader(listing), "00:1d:43", 200, "net:[1]", lookup) {
		t.Fatal("the own process counted as a foreign holder")
	}
	denied := func(int) (string, error) { return "", unix.EACCES }
	if !foreignNetworkNamespaceLockHolder(strings.NewReader(listing), "00:1d:42", 1, "net:[1]", denied) {
		t.Fatal("a holder whose namespace cannot be read did not count as foreign")
	}
}
