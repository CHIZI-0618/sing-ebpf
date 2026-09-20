//go:build with_ebpf && (linux || android)

package core

import (
	"encoding/binary"
	"errors"
	"os"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	cgroupUDPReleaseRingSize            = 64 * 1024
	cgroupUDPUserspaceCleanupDeadline   = "deadline"
	cgroupUDPUserspaceCleanupRingBuffer = "ringbuf"
)

func (b *CgroupBackend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

// AttachModes returns the effective attach mechanism per loaded cgroup
// program. It is a diagnostic snapshot only; it never probes or changes
// attachments and therefore is safe to call from the request-driven API.
func (b *CgroupBackend) AttachModes() map[string]string {
	result := make(map[string]string)
	if b == nil {
		return result
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return result
	}
	for slot, mode := range b.runtime.attach_modes {
		if mode == "" || !b.runtime.attached[slot] {
			continue
		}
		result[cgroupProgramDefinitions[slot].kernelProgramName] = mode
	}
	return result
}

// AttachMode summarizes the path actually used for the cgroup programs. A
// mixed result is possible when a vendor kernel treats attach types
// differently; callers should prefer AttachModes when they need per-hook
// detail.
func (b *CgroupBackend) AttachMode() string {
	modes := b.AttachModes()
	var selected string
	for _, mode := range modes {
		if selected == "" {
			selected = mode
		} else if selected != mode {
			return "mixed"
		}
	}
	if selected == "" {
		return "disabled"
	}
	return selected
}

func (b *CgroupBackend) UDPCleanupMode() string {
	if b == nil {
		return cgroupUDPCleanupDisabled
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return cgroupUDPCleanupModeLocked(b.runtime)
}

func (b *CgroupBackend) UDPTimeMode() string {
	if b == nil {
		return "disabled"
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		return "disabled"
	}
	if b.runtime.coarse_time_supported {
		return "coarse"
	}
	return "precise"
}

func (b *CgroupBackend) UDPStorageMode() string {
	if b == nil {
		return "disabled"
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		return "disabled"
	}
	if b.runtime.socket_storage_supported {
		return "socket_storage"
	}
	return "lru"
}

func (b *CgroupBackend) UDPUserspaceCleanupMode() string {
	if b == nil {
		return cgroupUDPUserspaceCleanupDeadline
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime != nil && b.runtime.enable_udp && b.runtime.udp_release_observer &&
		b.runtime.udp_release_reader != nil {
		return cgroupUDPUserspaceCleanupRingBuffer
	}
	return cgroupUDPUserspaceCleanupDeadline
}

// UDPReleaseNotificationDrops returns the number of socket-release events
// that could not be submitted because the optional ring buffer was full.
// It is read only when diagnostics are requested and does not add polling or
// userspace work to the normal data path.
func (b *CgroupBackend) UDPReleaseNotificationDrops() (uint64, error) {
	if b == nil {
		return 0, unix.EOPNOTSUPP
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.udp_release_observer {
		return 0, unix.EOPNOTSUPP
	}
	statsMap := b.runtime.maps["cgroup_udp_release_stats"]
	if statsMap == nil {
		return 0, unix.EOPNOTSUPP
	}
	index := uint32(0)
	var perCPU []uint64
	if err := statsMap.Lookup(&index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range perCPU {
		total += value
	}
	return total, nil
}

// ReadUDPRelease blocks until the cgroup socket-release hook reports a socket
// cookie that entered the local UDP data path. The notification is optional:
// callers must retain their normal UDP deadline for unsupported kernels and
// ring-buffer overflow.
func (b *CgroupBackend) ReadUDPRelease() (uint64, error) {
	if b == nil {
		return 0, unix.EOPNOTSUPP
	}
	b.access.RLock()
	runtimeState := b.runtime
	if runtimeState == nil || !runtimeState.udp_release_observer || runtimeState.udp_release_reader == nil {
		b.access.RUnlock()
		return 0, unix.EOPNOTSUPP
	}
	reader := runtimeState.udp_release_reader
	b.access.RUnlock()

	b.udpReleaseReadAccess.Lock()
	defer b.udpReleaseReadAccess.Unlock()
	if err := reader.ReadInto(&runtimeState.udp_release_record); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	sample := runtimeState.udp_release_record.RawSample
	if len(sample) != 8 {
		return 0, unix.EPROTO
	}
	return binary.NativeEndian.Uint64(sample), nil
}

func cgroupUDPCleanupModeLocked(runtimeState *cgroupRuntime) string {
	if runtimeState == nil || !runtimeState.enable_udp {
		return cgroupUDPCleanupDisabled
	}
	if !runtimeState.socket_release_supported {
		return cgroupUDPCleanupLRUFallback
	}
	if len(runtimeState.programs) <= cgroupProgramSocketRelease ||
		runtimeState.programs[cgroupProgramSocketRelease] == nil {
		return cgroupUDPCleanupInvalid
	}
	return cgroupUDPCleanupSocketRelease
}
