//go:build with_ebpf && (linux || android)

package core

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestCgroupNetworkGenerationABI(t *testing.T) {
	if size := unsafe.Sizeof(cgroupControl{}); size != 72 {
		t.Fatalf("unexpected cgroup control size: %d", size)
	}
	if offset := unsafe.Offsetof(cgroupControl{}.NetworkGeneration); offset != 4 {
		t.Fatalf("unexpected cgroup network generation offset: %d", offset)
	}
	if size := unsafe.Sizeof(udpFlowValue{}); size != 32 {
		t.Fatalf("unexpected cgroup UDP flow value size: %d", size)
	}
	if offset := unsafe.Offsetof(udpFlowValue{}.NetworkGeneration); offset != 28 {
		t.Fatalf("unexpected UDP flow network generation offset: %d", offset)
	}
	if size := unsafe.Sizeof(udpTokenReverseValue{}); size != 16 {
		t.Fatalf("unexpected UDP token reverse value size: %d", size)
	}
	if offset := unsafe.Offsetof(udpTokenReverseValue{}.NetworkGeneration); offset != 8 {
		t.Fatalf("unexpected UDP token reverse generation offset: %d", offset)
	}
}

func TestCgroupUDPMapConfigurationKeepsFlowCacheWithoutSocketRelease(t *testing.T) {
	capacity := DefaultCgroupMapCapacity()
	for _, socketReleaseSupported := range []bool{false, true} {
		layout := cgroupUDPMapConfiguration(true, socketReleaseSupported, capacity)
		if layout.flowCapacity != capacity.UDPFlow {
			t.Fatalf("socket_release=%v: flow capacity=%d, want %d", socketReleaseSupported, layout.flowCapacity, capacity.UDPFlow)
		}
	}
	if layout := cgroupUDPMapConfiguration(false, false, capacity); layout.flowCapacity != 1 {
		t.Fatalf("UDP-disabled layout changed flow capacity: got %d, want 1", layout.flowCapacity)
	}
}

func TestMapPressureLevels(t *testing.T) {
	for _, testCase := range []struct {
		entries, capacity uint32
		failed            bool
		want              string
	}{
		{10, 100, false, "healthy"},
		{85, 100, false, "warning"},
		{95, 100, false, "degraded"},
		{0, 100, true, "recovery_failed"},
	} {
		if got := mapPressure(testCase.entries, testCase.capacity, testCase.failed); got != testCase.want {
			t.Fatalf("mapPressure(%d/%d, %v)=%q, want %q", testCase.entries, testCase.capacity, testCase.failed, got, testCase.want)
		}
	}
}

func TestMapOccupancyStatusIgnoresNonApplicableMaps(t *testing.T) {
	status := mapOccupancyStatus([]MapOccupancy{
		{Pressure: "not_applicable", Supported: false},
		{Pressure: "healthy", Supported: true},
	})
	if status != "pass" {
		t.Fatalf("map occupancy status = %q, want pass", status)
	}
	status = mapOccupancyStatus([]MapOccupancy{
		{Pressure: "not_applicable", Supported: false},
		{Pressure: "warning", Supported: true},
	})
	if status != "warning" {
		t.Fatalf("map occupancy status = %q, want warning", status)
	}
}

func TestUDPReleasePathDiagnosticsReportsFallback(t *testing.T) {
	backend := &CgroupBackend{runtime: &cgroupRuntime{
		enable_udp:                  true,
		socket_release_supported:    true,
		udp_release_fallback_reason: "release_notification_program_load_failed",
	}}
	observer, reason, program := backend.UDPReleasePathDiagnostics()
	if observer || reason != "release_notification_program_load_failed" || program != "sb_ebpf_rel" {
		t.Fatalf("release path = observer=%t reason=%q program=%q", observer, reason, program)
	}
}

func TestSocketReleaseAttachPermissionFallsBack(t *testing.T) {
	for _, errno := range []error{unix.EPERM, unix.EACCES} {
		if !socketReleaseAttachUnavailable(fmt.Errorf("attach socket release: %w", errno)) {
			t.Fatalf("attach error %v did not select the LRU fallback", errno)
		}
		if socketReleaseUnavailable(errno) {
			t.Fatalf("permission error %v was treated as general socket-release unavailability", errno)
		}
		if !socketReleaseProbeUnavailable(errno) {
			t.Fatalf("permission error %v did not downgrade the optional probe", errno)
		}
	}
	if socketReleaseAttachUnavailable(unix.EBADF) {
		t.Fatal("unrelated socket-release attach error selected the LRU fallback")
	}
}

func TestSocketReleaseProbeKeepsRequiredPermissionErrorsFatal(t *testing.T) {
	if socketReleaseProbeUnavailable(unix.EBADF) {
		t.Fatal("unrelated probe error was downgraded")
	}
	if socketReleaseUnavailable(unix.EPERM) {
		t.Fatal("required attach classifier must not treat permission as generic absence")
	}
}

func TestCgroupAttachModeReportsOnlyAttachedPrograms(t *testing.T) {
	backend := &CgroupBackend{runtime: &cgroupRuntime{
		attached:     [cgroupProgramCount]bool{true, true, false},
		attach_modes: [cgroupProgramCount]string{"link_create", "legacy_exclusive"},
	}}
	if got := backend.AttachMode(); got != "mixed" {
		t.Fatalf("attach mode = %q, want mixed", got)
	}
	modes := backend.AttachModes()
	if modes[kernelProgramNameCgroupConnect4] != "link_create" || modes[kernelProgramNameCgroupSendmsg4] != "legacy_exclusive" {
		t.Fatalf("unexpected attach modes: %#v", modes)
	}
}
