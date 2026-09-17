//go:build with_ebpf && (linux || android)

package core

import (
	"testing"
	"unsafe"
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
