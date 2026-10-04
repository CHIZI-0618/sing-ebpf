//go:build with_ebpf && (linux || android)

package core

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// UDPReleaseEvent identifies the recovery entry created when a UDP socket was
// released. It is emitted only by the optional socket-release ring buffer.
// The timestamp uses the same monotonic clock as recovery values and is used
// for ABA-safe delayed cleanup.
type UDPReleaseEvent struct {
	SocketCookie      uint64
	Listener          netip.AddrPort
	NetworkGeneration uint32
	ReleasedAtNS      uint64
}

const (
	cgroupUDPReleaseRingSize            = 64 * 1024
	cgroupUDPUserspaceCleanupDeadline   = "deadline"
	cgroupUDPUserspaceCleanupRingBuffer = "ringbuf"
	cgroupUDPStateFull                  = "full"
	cgroupUDPStateSocketRelease         = "socket_release"
	cgroupUDPStateReleaseNotification   = "release_notification"
	cgroupUDPStateTimeoutFallback       = "timeout_fallback"
	cgroupUDPStateRecoveryDegraded      = "recovery_degraded"
	cgroupUDPStateMapPressure           = "map_pressure"
)

// UDPStateDiagnostics describes the effective cleanup and recovery path. It
// is a snapshot and performs no map iteration or probing.
type UDPStateDiagnostics struct {
	State                string `json:"state"`
	CleanupMode          string `json:"cleanup_mode"`
	UserspaceCleanupMode string `json:"userspace_cleanup_mode"`
	RecoveryMode         string `json:"recovery_mode"`
	RecoveryConsumeMode  string `json:"recovery_consume_mode"`
	SocketRelease        bool   `json:"socket_release"`
	NetworkGeneration    uint32 `json:"network_generation"`
	MapPressure          string `json:"map_pressure"`
}

func (b *CgroupBackend) UDPStateDiagnostics() UDPStateDiagnostics {
	result := UDPStateDiagnostics{State: cgroupUDPStateFull, RecoveryMode: "reverse_index", RecoveryConsumeMode: "unknown"}
	if b == nil {
		result.State = cgroupUDPStateRecoveryDegraded
		return result
	}
	result.RecoveryConsumeMode = b.udpRecoveryConsumeModeString()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || !b.runtime.enable_udp {
		result.State = cgroupUDPCleanupDisabled
		result.CleanupMode = cgroupUDPCleanupDisabled
		result.UserspaceCleanupMode = cgroupUDPCleanupDisabled
		result.RecoveryMode = "disabled"
		return result
	}
	result.CleanupMode = cgroupUDPCleanupModeLocked(b.runtime)
	result.UserspaceCleanupMode = cgroupUDPUserspaceCleanupModeLocked(b.runtime)
	result.SocketRelease = b.runtime.socket_release_supported
	result.NetworkGeneration = b.networkGeneration
	if result.SocketRelease {
		result.State = cgroupUDPStateSocketRelease
		if result.UserspaceCleanupMode == cgroupUDPUserspaceCleanupRingBuffer {
			result.State = cgroupUDPStateReleaseNotification
		}
	} else {
		result.State = cgroupUDPStateTimeoutFallback
	}
	return result
}

func (b *CgroupBackend) udpRecoveryConsumeModeString() string {
	switch b.udpRecoveryConsumeMode.Load() {
	case mapLookupAndDeleteSupported:
		return "lookup_and_delete"
	case mapLookupAndDeleteUnsupported:
		return "lookup_only"
	default:
		return "unknown"
	}
}

func cgroupUDPUserspaceCleanupModeLocked(runtimeState *cgroupRuntime) string {
	if runtimeState != nil && runtimeState.enable_udp && runtimeState.udp_release_observer && runtimeState.udp_release_reader != nil {
		return cgroupUDPUserspaceCleanupRingBuffer
	}
	return cgroupUDPUserspaceCleanupDeadline
}

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
	return "lru"
}

func (b *CgroupBackend) UDPUserspaceCleanupMode() string {
	if b == nil {
		return cgroupUDPUserspaceCleanupDeadline
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return cgroupUDPUserspaceCleanupModeLocked(b.runtime)
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

// ReadUDPRelease blocks until the cgroup socket-release hook reports a UDP
// recovery entry. The notification is optional:
// callers must retain their normal UDP deadline for unsupported kernels and
// ring-buffer overflow.
func (b *CgroupBackend) ReadUDPRelease() (UDPReleaseEvent, error) {
	if b == nil {
		return UDPReleaseEvent{}, unix.EOPNOTSUPP
	}
	b.access.RLock()
	runtimeState := b.runtime
	if runtimeState == nil || !runtimeState.udp_release_observer || runtimeState.udp_release_reader == nil {
		b.access.RUnlock()
		return UDPReleaseEvent{}, unix.EOPNOTSUPP
	}
	reader := runtimeState.udp_release_reader
	b.access.RUnlock()

	b.udpReleaseReadAccess.Lock()
	defer b.udpReleaseReadAccess.Unlock()
	if err := reader.ReadInto(&runtimeState.udp_release_record); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return UDPReleaseEvent{}, os.ErrClosed
		}
		return UDPReleaseEvent{}, err
	}
	sample := runtimeState.udp_release_record.RawSample
	if len(sample) != 40 {
		return UDPReleaseEvent{}, unix.EPROTO
	}
	var key listenerLookupKey
	key.Family = sample[8]
	key.Protocol = sample[9]
	key.ListenerPort = binary.NativeEndian.Uint16(sample[10:12])
	copy(key.TokenAddr[:], sample[12:28])
	if key.Protocol != ProtocolUDP {
		return UDPReleaseEvent{}, unix.EPROTO
	}
	listener, err := listenerDestinationFromKey(key)
	if err != nil {
		return UDPReleaseEvent{}, E.Cause(err, "decode UDP release listener")
	}
	return UDPReleaseEvent{
		SocketCookie:      binary.NativeEndian.Uint64(sample[0:8]),
		Listener:          listener,
		NetworkGeneration: binary.NativeEndian.Uint32(sample[28:32]),
		ReleasedAtNS:      binary.NativeEndian.Uint64(sample[32:40]),
	}, nil
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
