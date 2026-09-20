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
