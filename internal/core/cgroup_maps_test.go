//go:build with_ebpf && (linux || android)

package core

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

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
	}
	if socketReleaseAttachUnavailable(unix.EBADF) {
		t.Fatal("unrelated socket-release attach error selected the LRU fallback")
	}
}
