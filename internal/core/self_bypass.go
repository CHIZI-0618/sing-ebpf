//go:build with_ebpf && (linux || android)

package core

import (
	"bufio"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

const (
	// Socket-cookie entries are short-lived runtime state. The LRU fallback
	// bounds stale entries, so use a smaller default while retaining room for
	// normal concurrent sockets.
	selfBypassSocketCapacity        = 16384
	CompactSelfBypassSocketCapacity = 8192
)

// SelfBypass owns the socket-cookie metadata fallback used by the local TC
// classifier. Self-bypass flags are populated by process cgroup hooks or
// socket controls.
// ProcessTracker may also write application UID policy flags into this map;
// those entries require the tracker's wider cgroup release coverage.
//
// The kernel map is created on first use rather than by the constructor.
// Consumers construct SelfBypass while building their configuration, and
// that step also runs where no BPF privilege exists: configuration checks,
// including the unprivileged worker of a desktop client. Creating the map
// there fails with EPERM although the privileged runtime could use it.
// Every path that needs the map creates it first: data-plane preparation
// (through PreparedMap), cgroup attachment, and socket registration.
type SelfBypass struct {
	access            sync.RWMutex
	capacity          uint32
	sockets           *CiliumEBPF.Map
	storage           *CiliumEBPF.Map
	storageRequested  bool
	storageProducer   bool
	storageActive     bool
	closed            bool
	programs          []*CiliumEBPF.Program
	links             []cgroupProgramLink
	mode              atomic.Uint32
	lifecycle         atomic.Uint32
	decisionBackend   string
	producerBackend   string
	visibilityBackend string
	cleanupBackend    string
	reclaimBackend    string
	attachmentBackend string
	fallbackReason    string
	reclaimAttempts   atomic.Uint64
	reclaimedSockets  atomic.Uint64
	reclaimFailures   atomic.Uint64
	reclaimLastAt     atomic.Int64
	storageWriteFails atomic.Uint64
	cookieFallbacks   atomic.Uint64
	directTGID        uint32
	directFallback    SelfBypassCgroupConfig
	cgroupPath        string
	cgroupConfig      SelfBypassCgroupConfig
	cgroupOwnerTGID   uint32
}

type SelfBypassCgroupConfig struct {
	EnableTCP  bool
	EnableUDP  bool
	EnableIPv6 bool
	Direct     bool
	// EnableSocketStorage requests the optional TC socket-local visibility
	// backend. It never changes the selected data plane and remains subject to
	// map, helper and representative object-load fallback.
	EnableSocketStorage bool
}

type SelfBypassMode uint32

const (
	selfBypassLifecycleConfigured = 1 << iota
	selfBypassLifecycleRegistration
	selfBypassLifecycleUnregister
)

const (
	SelfBypassUserspace SelfBypassMode = iota
	SelfBypassCgroupSocket
	// SelfBypassCgroupSocketAddrRelease combines socket-address registration with
	// sock_release cleanup. The release hook is best-effort because vendor
	// kernels may reject it while accepting the address hooks.
	SelfBypassCgroupSocketAddrRelease
	// SelfBypassUserspaceRelease keeps userspace socket registration while
	// using a cgroup sock_release hook for lifecycle cleanup. This is useful
	// when socket-create/connect hooks are unavailable, including TC-only
	// deployments where the cgroup data plane is not loaded.
	SelfBypassUserspaceRelease
	// SelfBypassCgroupSocketAddr uses connect/sendmsg hooks and userspace
	// cookie cleanup when the kernel has no usable sock_release hook.
	SelfBypassCgroupSocketAddr
	// SelfBypassDirectTGID lets the local cgroup data plane compare the current
	// TGID directly without publishing per-socket cookie state.
	SelfBypassDirectTGID
)

func (m SelfBypassMode) String() string {
	switch m {
	case SelfBypassCgroupSocket:
		return "cgroup_socket_cookie"
	case SelfBypassCgroupSocketAddr:
		return "cgroup_socket_addr"
	case SelfBypassCgroupSocketAddrRelease:
		return "cgroup_socket_addr_release"
	case SelfBypassUserspaceRelease:
		return "userspace_socket_cookie_release"
	case SelfBypassDirectTGID:
		return "direct_tgid"
	default:
		return "userspace_socket_cookie"
	}
}

// SelfBypassDiagnostics describes the independently selected ownership and
// cleanup paths. Mode is retained as a compatibility summary for callers that
// still consume the historical composite enum.
type SelfBypassDiagnostics struct {
	Mode              string `json:"mode"`
	DecisionBackend   string `json:"decision_backend"`
	ProducerBackend   string `json:"producer_backend"`
	VisibilityBackend string `json:"visibility_backend"`
	CleanupBackend    string `json:"cleanup_backend"`
	ReclaimBackend    string `json:"reclaim_backend"`
	AttachmentBackend string `json:"attachment_backend"`
	FallbackReason    string `json:"fallback_reason,omitempty"`
	ReclaimAttempts   uint64 `json:"reclaim_attempts"`
	ReclaimedSockets  uint64 `json:"reclaimed_sockets"`
	ReclaimFailures   uint64 `json:"reclaim_failures"`
	ReclaimLastAt     int64  `json:"reclaim_last_at,omitempty"`
	StorageWriteFails uint64 `json:"storage_write_failures"`
	CookieFallbacks   uint64 `json:"cookie_fallbacks"`
}

// SocketRegistration is the lifecycle token returned for a userspace-published
// socket cookie. A zero value means that the selected producer did not require
// userspace registration.
type SocketRegistration struct {
	Cookie uint64
}

func (r SocketRegistration) Active() bool { return r.Cookie != 0 }

const (
	selfBypassDecisionCgroupTGID   = "cgroup_tgid"
	selfBypassDecisionDirectTGID   = "direct_tgid"
	selfBypassDecisionUserspace    = "userspace_control"
	selfBypassProducerSocketCreate = "cgroup_sock_create"
	selfBypassProducerCgroupAddr   = "cgroup_addr"
	selfBypassProducerUserspace    = "userspace_control"
	selfBypassProducerNone         = "none"
	selfBypassVisibilityCookieHash = "cookie_hash"
	selfBypassVisibilitySKStorage  = "sk_storage"
	selfBypassVisibilityDirectTGID = "direct_tgid"
	selfBypassCleanupSocketRelease = "socket_release"
	selfBypassCleanupUserspace     = "userspace_unregister"
	selfBypassCleanupNone          = "none"
	selfBypassCleanupSKStorage     = "sk_storage"
	selfBypassReclaimProcFD        = "proc_fd_reclaim"
	// struct bpf_sock_addr places its kernel socket pointer after the writable
	// address fields. __bpf_md_ptr is 8-byte aligned, so this offset is stable
	// on supported 32-bit and 64-bit ABIs.
	bpfSockAddrSocketOffset = 64
)

// CleanupMode reports how entries in the self-bypass map are removed.
// UserspaceRelease deliberately reports userspace_unregister as well: its
// release hook is only a fallback, while the owner that registered the socket
// remains responsible for deleting it before close.
func (m SelfBypassMode) CleanupMode() string {
	switch m {
	case SelfBypassCgroupSocket, SelfBypassCgroupSocketAddrRelease:
		return "socket_release"
	case SelfBypassDirectTGID:
		return "none"
	default:
		return "userspace_unregister"
	}
}

func NewSelfBypass() (*SelfBypass, error) {
	return NewSelfBypassWithCapacity(selfBypassSocketCapacity)
}

func NewSelfBypassWithCapacity(capacity uint32) (*SelfBypass, error) {
	if capacity == 0 || capacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid eBPF self-bypass socket map capacity: ", capacity)
	}
	return &SelfBypass{
		capacity: capacity,
	}, nil
}

var errSelfBypassClosed = E.New("eBPF self-bypass is closed")

// Prepare creates the socket-cookie map if it does not exist yet. It reports
// the same errors map creation would, so a privileged runtime can surface
// missing privileges at startup instead of at the first dial.
func (b *SelfBypass) Prepare() error {
	_, err := b.PreparedMap()
	return err
}

// PreparedMap returns the socket-cookie map, creating it first if needed.
// Data planes that share the map must use it instead of Map: a data plane
// that silently created its own map would never see registered sockets.
func (b *SelfBypass) PreparedMap() (*CiliumEBPF.Map, error) {
	if b == nil {
		return nil, E.New("eBPF self-bypass map is unavailable")
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.prepareMapLocked()
}

func (b *SelfBypass) prepareMapLocked() (*CiliumEBPF.Map, error) {
	if b.closed {
		return nil, errSelfBypassClosed
	}
	if b.sockets != nil {
		return b.sockets, nil
	}
	if b.capacity == 0 {
		return nil, E.New("eBPF self-bypass map is unavailable")
	}
	// This is usually the first BPF object a consumer creates, so its EPERM is
	// where a missing privilege first surfaces. Explain it precisely.
	memlockErr := raiseMemlockLimit()
	sockets, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_self_sockets",
		Type:       CiliumEBPF.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: b.capacity,
		Flags:      bpfFlagNoPrealloc,
	})
	if err != nil {
		return nil, E.Cause(explainBPFPermissionError(err, memlockErr), "create eBPF self-bypass socket map")
	}
	b.sockets = sockets
	return sockets, nil
}

// selfBypassStorageKeyType and selfBypassStorageValueType describe the local
// storage ABI required by the kernel. The key is a socket FD for userspace
// operations; BPF programs address the same entry through the socket pointer.
func selfBypassStorageKeyType() btf.Type {
	return &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
}

func selfBypassStorageValueType() btf.Type {
	return &btf.Int{Name: "__u32", Size: 4, Encoding: btf.Unsigned}
}

func selfBypassStorageMapSpec() *CiliumEBPF.MapSpec {
	return &CiliumEBPF.MapSpec{
		Name:       "sb_self_store",
		Type:       CiliumEBPF.SkStorage,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 0,
		Flags:      bpfFlagNoPrealloc,
		Key:        selfBypassStorageKeyType(),
		Value:      selfBypassStorageValueType(),
	}
}

func (b *SelfBypass) prepareStorageLocked() (*CiliumEBPF.Map, error) {
	if b.closed {
		return nil, errSelfBypassClosed
	}
	if b.storage != nil {
		return b.storage, nil
	}
	memlockErr := raiseMemlockLimit()
	storage, err := CiliumEBPF.NewMap(selfBypassStorageMapSpec())
	if err != nil {
		return nil, E.Cause(explainBPFPermissionError(err, memlockErr), "create eBPF self-bypass socket storage map")
	}
	b.storage = storage
	return storage, nil
}

// beginStorageSelection returns the optional socket-local map requested for a
// local TC data path. Each representative object load must select the active
// reader again: a previous TC runtime may have used storage while its
// replacement falls back to the cookie object on the same vendor kernel.
func (b *SelfBypass) beginStorageSelection() *CiliumEBPF.Map {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if !b.storageRequested || b.closed {
		return nil
	}
	b.storageActive = false
	return b.storage
}

// ActivateStorage records that the representative TC storage object actually
// loaded. Preliminary map or cgroup helper success alone must not advertise
// the fast path. The cookie hash remains a per-socket fallback and transition
// bridge for sockets created before activation.
func (b *SelfBypass) ActivateStorage() {
	if b == nil {
		return
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed || b.storage == nil || b.mode.Load() == uint32(SelfBypassDirectTGID) {
		return
	}
	b.storageActive = true
	b.visibilityBackend = selfBypassVisibilitySKStorage
	b.cleanupBackend = selfBypassCleanupSKStorage
	if b.storageProducer {
		if b.mode.Load() == uint32(SelfBypassCgroupSocketAddr) {
			// Address hooks own publication, while userspace still removes the
			// cookie shadow when sock_release is unavailable.
			b.producerBackend = selfBypassProducerCgroupAddr
			b.reclaimBackend = selfBypassReclaimProcFD
			b.setLifecycleNeeds(true, true)
		}
		return
	}
	// A non-exclusive cgroup cannot safely publish metadata for only this
	// process. Userspace writes storage through the live socket FD instead.
	b.producerBackend = selfBypassProducerUserspace
	b.reclaimBackend = selfBypassReclaimProcFD
	b.setLifecycleNeeds(true, true)
}

func (b *SelfBypass) setStorageFallback(reason string) {
	if b == nil || reason == "" {
		return
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.storageRequested && !b.storageActive {
		mode := SelfBypassMode(b.mode.Load())
		if b.storageProducer {
			if err := b.rollbackStorageProducerLocked(); err != nil {
				b.mode.Store(uint32(SelfBypassUserspace))
				b.setPathDiagnostics(selfBypassDecisionUserspace, selfBypassProducerUserspace, selfBypassCleanupUserspace)
				reason = "tc_storage_writer_rollback_failed"
				mode = SelfBypassUserspace
			}
		}
		b.setCookiePathDiagnosticsLocked(mode)
		b.storageRequested = false
		_ = b.closeStorageLocked()
		b.fallbackReason = reason
	}
}

func (b *SelfBypass) setCookiePathDiagnosticsLocked(mode SelfBypassMode) {
	switch mode {
	case SelfBypassCgroupSocket:
		b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerSocketCreate, selfBypassCleanupSocketRelease)
	case SelfBypassCgroupSocketAddrRelease:
		b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerCgroupAddr, selfBypassCleanupSocketRelease)
	case SelfBypassCgroupSocketAddr:
		b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerUserspace, selfBypassCleanupUserspace)
	default:
		b.setPathDiagnostics(selfBypassDecisionUserspace, selfBypassProducerUserspace, selfBypassCleanupUserspace)
	}
}

func (b *SelfBypass) rollbackStorageProducerLocked() error {
	mode := SelfBypassMode(b.mode.Load())
	if err := b.closeHooks(); err != nil {
		return err
	}
	var err error
	switch mode {
	case SelfBypassCgroupSocket:
		err = b.attachCgroupSocket(b.cgroupPath, b.cgroupOwnerTGID, -1)
		if err == nil {
			err = b.verifyOwnerMetadata(false, b.cgroupConfig, false)
		}
		if err == nil {
			b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerSocketCreate, selfBypassCleanupSocketRelease)
		}
	case SelfBypassCgroupSocketAddr, SelfBypassCgroupSocketAddrRelease:
		err = b.attachCgroupSocketAddr(b.cgroupPath, b.cgroupConfig, b.cgroupOwnerTGID, -1)
		if err == nil {
			err = b.verifyOwnerMetadata(true, b.cgroupConfig, false)
		}
		if err == nil && mode == SelfBypassCgroupSocketAddrRelease {
			err = b.attachCgroupRelease(b.cgroupPath, false)
		}
		if err == nil {
			producer := selfBypassProducerCgroupAddr
			cleanup := selfBypassCleanupSocketRelease
			if mode == SelfBypassCgroupSocketAddr {
				producer = selfBypassProducerUserspace
				cleanup = selfBypassCleanupUserspace
			}
			b.setPathDiagnostics(selfBypassDecisionCgroupTGID, producer, cleanup)
		}
	default:
		return nil
	}
	if err != nil {
		return E.Errors(err, b.closeHooks())
	}
	b.mode.Store(uint32(mode))
	b.storageProducer = false
	return nil
}

func (b *SelfBypass) closeStorageLocked() error {
	if b.storage == nil {
		return nil
	}
	err := b.storage.Close()
	if err == nil {
		b.storage = nil
	}
	return err
}

// Map returns the map that must be shared with the local TC programs, or nil
// before it has been created; use PreparedMap to create it. The map is
// borrowed: callers must not close or retain it beyond SelfBypass.Close.
func (b *SelfBypass) Map() *CiliumEBPF.Map {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets
}

// AttachCgroup enables automatic socket-cookie registration when the current
// cgroup is exclusive to this process. It first tries socket create/release
// hooks, then connect/sendmsg hooks for kernels that expose only the latter.
// The metadata hooks only record sockets of this process's own thread group:
// child processes started later inherit the cgroup (an embedded SSH server's
// sessions, for example) and must stay subject to interception. After
// attaching, a probe socket must be recorded; otherwise the hooks are removed.
// When those hooks cannot be used, it still attempts a release-only hook so
// userspace registration does not leave entries behind on pure TC systems.
// A failure leaves the map usable by the userspace registration fallback.
func (b *SelfBypass) AttachCgroup(config SelfBypassCgroupConfig) error {
	if b == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if _, err := b.prepareMapLocked(); err != nil {
		return err
	}
	if b.mode.Load() != uint32(SelfBypassUserspace) {
		return nil
	}
	b.fallbackReason = ""
	if config.Direct {
		ownerTGID, ownerErr := selfBypassOwner()
		if ownerErr == nil && features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnGetCurrentPidTgid) == nil {
			config.Direct = false
			b.directTGID = ownerTGID
			b.directFallback = config
			b.decisionBackend = selfBypassDecisionDirectTGID
			b.producerBackend = selfBypassProducerNone
			b.visibilityBackend = selfBypassVisibilityDirectTGID
			b.cleanupBackend = selfBypassCleanupNone
			b.reclaimBackend = "none"
			b.attachmentBackend = "none"
			b.setLifecycleNeeds(false, false)
			b.mode.Store(uint32(SelfBypassDirectTGID))
			return nil
		}
		if ownerErr != nil {
			b.fallbackReason = "direct_tgid_owner_unavailable"
		} else {
			b.fallbackReason = "direct_tgid_helper_unavailable"
		}
	}
	b.storageRequested = config.EnableSocketStorage
	storageFD := -1
	if b.storageRequested {
		if storage, storageErr := b.prepareStorageLocked(); storageErr == nil {
			storageFD = storage.FD()
		} else {
			b.fallbackReason = "sk_storage_map_unavailable"
		}
	}
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		if err := b.closeHooks(); err != nil {
			return E.Cause(err, "finish previous eBPF self-bypass cleanup")
		}
	}
	cgroupPath, err := DetectProcessCgroup2Path()
	if err != nil {
		b.fallbackReason = "cgroup_path_unavailable"
		return E.Cause(err, "detect process cgroup v2")
	}
	exclusive, exclusiveErr := processCgroupExclusive(cgroupPath)
	var attachErrors []error
	if exclusiveErr != nil {
		attachErrors = append(attachErrors, exclusiveErr)
	}
	var ownerTGID uint32
	if exclusive {
		var ownerErr error
		ownerTGID, ownerErr = selfBypassOwner()
		if ownerErr != nil {
			attachErrors = append(attachErrors, ownerErr)
			exclusive = false
		}
	} else if exclusiveErr == nil {
		attachErrors = append(attachErrors, E.New("process cgroup contains other processes"))
	}
	if exclusive {
		b.cgroupPath = cgroupPath
		b.cgroupConfig = config
		b.cgroupOwnerTGID = ownerTGID
		createStorageFD := storageFD
		createReleaseErr := b.attachCgroupSocket(cgroupPath, ownerTGID, createStorageFD)
		if createReleaseErr == nil {
			createReleaseErr = b.verifyOwnerMetadata(false, config, createStorageFD >= 0)
			if createReleaseErr == nil {
				b.storageProducer = createStorageFD >= 0
				b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerSocketCreate, selfBypassCleanupSocketRelease)
				b.mode.Store(uint32(SelfBypassCgroupSocket))
				return nil
			}
			if closeErr := b.closeHooks(); closeErr != nil {
				return E.Errors(createReleaseErr, closeErr)
			}
		}
		attachErrors = append(attachErrors, createReleaseErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
		if createStorageFD >= 0 {
			// The storage writer is optional. Retry the same strongest ownership
			// hook with the cookie-only program before falling back to later hooks.
			createReleaseErr = b.attachCgroupSocket(cgroupPath, ownerTGID, -1)
			if createReleaseErr == nil {
				createReleaseErr = b.verifyOwnerMetadata(false, config, false)
				if createReleaseErr == nil {
					b.fallbackReason = "sk_storage_cgroup_writer_unavailable"
					b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerSocketCreate, selfBypassCleanupSocketRelease)
					b.mode.Store(uint32(SelfBypassCgroupSocket))
					return nil
				}
				if closeErr := b.closeHooks(); closeErr != nil {
					return E.Errors(createReleaseErr, closeErr)
				}
			}
			attachErrors = append(attachErrors, createReleaseErr)
			if lenOpenCgroupProgramLinks(b.links) > 0 {
				return E.Errors(attachErrors...)
			}
		}
		socketAddrStorageFD := storageFD
		socketAddrErr := b.attachCgroupSocketAddr(cgroupPath, config, ownerTGID, socketAddrStorageFD)
		if socketAddrErr == nil {
			socketAddrErr = b.verifyOwnerMetadata(true, config, socketAddrStorageFD >= 0)
			if socketAddrErr == nil {
				if releaseErr := b.attachCgroupRelease(cgroupPath, false); releaseErr == nil {
					b.storageProducer = socketAddrStorageFD >= 0
					b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerCgroupAddr, selfBypassCleanupSocketRelease)
					b.mode.Store(uint32(SelfBypassCgroupSocketAddrRelease))
					return nil
				}
				// Keep the address hooks active and pair them with userspace cookie
				// registration. The registration wrapper provides exact cleanup;
				// closed-entry reclamation remains the last-resort safety net.
				b.fallbackReason = "socket_release_unavailable"
				b.storageProducer = socketAddrStorageFD >= 0
				b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerUserspace, selfBypassCleanupUserspace)
				b.mode.Store(uint32(SelfBypassCgroupSocketAddr))
				return nil
			}
			if closeErr := b.closeHooks(); closeErr != nil {
				return E.Errors(socketAddrErr, closeErr)
			}
		}
		attachErrors = append(attachErrors, socketAddrErr)
		if lenOpenCgroupProgramLinks(b.links) > 0 {
			return E.Errors(attachErrors...)
		}
		if socketAddrStorageFD >= 0 {
			socketAddrErr = b.attachCgroupSocketAddr(cgroupPath, config, ownerTGID, -1)
			if socketAddrErr == nil {
				socketAddrErr = b.verifyOwnerMetadata(true, config, false)
				if socketAddrErr == nil {
					if releaseErr := b.attachCgroupRelease(cgroupPath, false); releaseErr == nil {
						b.fallbackReason = "sk_storage_cgroup_writer_unavailable"
						b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerCgroupAddr, selfBypassCleanupSocketRelease)
						b.mode.Store(uint32(SelfBypassCgroupSocketAddrRelease))
						return nil
					}
					b.fallbackReason = "socket_release_unavailable"
					b.setPathDiagnostics(selfBypassDecisionCgroupTGID, selfBypassProducerUserspace, selfBypassCleanupUserspace)
					b.mode.Store(uint32(SelfBypassCgroupSocketAddr))
					return nil
				}
				if closeErr := b.closeHooks(); closeErr != nil {
					return E.Errors(socketAddrErr, closeErr)
				}
			}
			attachErrors = append(attachErrors, socketAddrErr)
			if lenOpenCgroupProgramLinks(b.links) > 0 {
				return E.Errors(attachErrors...)
			}
		}
	}

	// A release-only hook is safe on a shared cgroup: it only deletes entries
	// whose cookies are already present in our map, and never marks sockets.
	// The process cgroup is shared in this branch.  A release-only helper is
	// optional and must never turn a shared hook into legacy single-program
	// mode, otherwise the interception backend cannot attach its own
	// multi-program/link hook afterwards.
	if releaseErr := b.attachCgroupRelease(cgroupPath, true); releaseErr == nil {
		b.setPathDiagnostics(selfBypassDecisionUserspace, selfBypassProducerUserspace, selfBypassCleanupUserspace)
		b.mode.Store(uint32(SelfBypassUserspaceRelease))
		b.fallbackReason = "cgroup_socket_hooks_unavailable"
		return nil
	} else {
		b.fallbackReason = "cgroup_hooks_unavailable"
		attachErrors = append(attachErrors, releaseErr)
	}
	return E.Errors(attachErrors...)
}

func (b *SelfBypass) setPathDiagnostics(decision, producer, cleanup string) {
	b.decisionBackend = decision
	b.producerBackend = producer
	b.visibilityBackend = selfBypassVisibilityCookieHash
	b.cleanupBackend = cleanup
	if producer == selfBypassProducerUserspace {
		b.reclaimBackend = selfBypassReclaimProcFD
	} else {
		b.reclaimBackend = "none"
	}
	b.attachmentBackend = b.currentAttachmentBackend()
	b.setLifecycleNeeds(producer == selfBypassProducerUserspace, cleanup == selfBypassCleanupUserspace)
}

func (b *SelfBypass) setLifecycleNeeds(registration, unregister bool) {
	state := uint32(selfBypassLifecycleConfigured)
	if registration {
		state |= selfBypassLifecycleRegistration
	}
	if unregister {
		state |= selfBypassLifecycleUnregister
	}
	b.lifecycle.Store(state)
}

func (b *SelfBypass) currentAttachmentBackend() string {
	if len(b.links) == 0 {
		return "none"
	}
	selected := ""
	for _, programLink := range b.links {
		if programLink == nil {
			continue
		}
		mode := cgroupProgramLinkMechanism(programLink)
		if selected == "" {
			selected = mode
		} else if selected != mode {
			return "mixed"
		}
	}
	if selected == "" {
		return "none"
	}
	return selected
}

// Diagnostics returns the actual ownership, metadata, cleanup and attachment
// paths selected after verifier/attach fallback. It performs no probing.
func (b *SelfBypass) Diagnostics() SelfBypassDiagnostics {
	if b == nil {
		return SelfBypassDiagnostics{
			Mode:              SelfBypassUserspace.String(),
			DecisionBackend:   selfBypassDecisionUserspace,
			ProducerBackend:   selfBypassProducerUserspace,
			VisibilityBackend: selfBypassVisibilityCookieHash,
			CleanupBackend:    selfBypassCleanupUserspace,
			ReclaimBackend:    selfBypassReclaimProcFD,
			AttachmentBackend: "none",
		}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	result := SelfBypassDiagnostics{
		Mode:              SelfBypassMode(b.mode.Load()).String(),
		DecisionBackend:   b.decisionBackend,
		ProducerBackend:   b.producerBackend,
		VisibilityBackend: b.visibilityBackend,
		CleanupBackend:    b.cleanupBackend,
		ReclaimBackend:    b.reclaimBackend,
		AttachmentBackend: b.attachmentBackend,
		FallbackReason:    b.fallbackReason,
		ReclaimAttempts:   b.reclaimAttempts.Load(),
		ReclaimedSockets:  b.reclaimedSockets.Load(),
		ReclaimFailures:   b.reclaimFailures.Load(),
		ReclaimLastAt:     b.reclaimLastAt.Load(),
		StorageWriteFails: b.storageWriteFails.Load(),
		CookieFallbacks:   b.cookieFallbacks.Load(),
	}
	if result.DecisionBackend == "" {
		result.DecisionBackend = selfBypassDecisionUserspace
	}
	if result.ProducerBackend == "" {
		result.ProducerBackend = selfBypassProducerUserspace
	}
	if result.VisibilityBackend == "" {
		result.VisibilityBackend = selfBypassVisibilityCookieHash
	}
	if result.CleanupBackend == "" {
		result.CleanupBackend = selfBypassCleanupUserspace
	}
	if result.ReclaimBackend == "" {
		result.ReclaimBackend = selfBypassReclaimProcFD
	}
	if result.AttachmentBackend == "" {
		result.AttachmentBackend = "none"
	}
	return result
}

// NeedsUserspaceRegistration reports whether socket controls must publish
// socket cookies into the shared visibility map.
func (b *SelfBypass) NeedsUserspaceRegistration() bool {
	if b == nil {
		return false
	}
	state := b.lifecycle.Load()
	return state == 0 || state&selfBypassLifecycleRegistration != 0
}

// NeedsUserspaceUnregister reports whether the userspace owner must release
// registrations before closing their sockets.
func (b *SelfBypass) NeedsUserspaceUnregister() bool {
	if b == nil {
		return false
	}
	state := b.lifecycle.Load()
	return state == 0 || state&selfBypassLifecycleUnregister != 0
}

// CleanupBackend reports the primary kernel/userspace cleanup path.
func (b *SelfBypass) CleanupBackend() string { return b.Diagnostics().CleanupBackend }

func (b *SelfBypass) CgroupAttached() bool {
	if b == nil {
		return false
	}
	mode := SelfBypassMode(b.mode.Load())
	return mode == SelfBypassCgroupSocket || mode == SelfBypassCgroupSocketAddr ||
		mode == SelfBypassCgroupSocketAddrRelease || mode == SelfBypassDirectTGID
}

func (b *SelfBypass) Mode() SelfBypassMode {
	if b == nil {
		return SelfBypassUserspace
	}
	return SelfBypassMode(b.mode.Load())
}

func (b *SelfBypass) DirectCgroupTGID() uint32 {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.directTGID
}

// fallbackDirectCgroup activates the cookie bridge after a representative
// direct-TGID object load failed on a vendor kernel. It is called before the
// interception programs attach, so the transition cannot expose a mixed path.
func (b *SelfBypass) fallbackDirectCgroup() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	if b.directTGID == 0 {
		b.access.Unlock()
		return nil
	}
	config := b.directFallback
	b.directTGID = 0
	b.directFallback = SelfBypassCgroupConfig{}
	b.mode.Store(uint32(SelfBypassUserspace))
	b.decisionBackend = ""
	b.producerBackend = ""
	b.visibilityBackend = ""
	b.cleanupBackend = ""
	b.reclaimBackend = ""
	b.attachmentBackend = "none"
	b.setLifecycleNeeds(true, true)
	b.fallbackReason = "direct_tgid_program_load_failed"
	b.access.Unlock()
	err := b.AttachCgroup(config)
	if err == nil {
		b.access.Lock()
		b.fallbackReason = "direct_tgid_program_load_failed"
		b.access.Unlock()
	}
	return err
}

// FallbackReason reports why the selected self-bypass mode fell back from a
// stronger cgroup hook set. It is empty when the socket-create mode is active.
func (b *SelfBypass) FallbackReason() string {
	if b == nil {
		return ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fallbackReason
}

func (b *SelfBypass) attachCgroupSocket(path string, ownerTGID uint32, storageFD int) error {
	createProgram, err := newSelfBypassCreateProgram(b.sockets.FD(), ownerTGID, storageFD)
	if err != nil {
		return err
	}
	releaseProgram, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		_ = createProgram.Close()
		return err
	}
	createLink, err := attachCgroupProgram(path, createProgram, CiliumEBPF.AttachCGroupInetSockCreate)
	if err != nil {
		_ = releaseProgram.Close()
		_ = createProgram.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-create hook")
	}
	releaseLink, err := attachCgroupProgram(path, releaseProgram, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		_ = releaseProgram.Close()
		b.programs = []*CiliumEBPF.Program{createProgram}
		b.links = []cgroupProgramLink{createLink}
		return E.Errors(
			E.Cause(err, "attach eBPF self-bypass socket-release hook"),
			b.closeHooks(),
		)
	}
	b.programs = []*CiliumEBPF.Program{createProgram, releaseProgram}
	b.links = []cgroupProgramLink{createLink, releaseLink}
	return nil
}

func (b *SelfBypass) attachCgroupRelease(path string, shared bool) error {
	program, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	var programLink cgroupProgramLink
	if shared {
		programLink, err = attachCgroupProgramShared(path, program, CiliumEBPF.AttachCgroupInetSockRelease)
	} else {
		programLink, err = attachCgroupProgram(path, program, CiliumEBPF.AttachCgroupInetSockRelease)
	}
	if err != nil {
		_ = program.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-release cleanup hook")
	}
	b.programs = append(b.programs, program)
	b.links = append(b.links, programLink)
	return nil
}

func (b *SelfBypass) attachCgroupSocketAddr(path string, config SelfBypassCgroupConfig, ownerTGID uint32, storageFD int) error {
	hooks := selfBypassSocketAddrHooks(config)
	programs := make([]*CiliumEBPF.Program, 0, len(hooks))
	links := make([]cgroupProgramLink, 0, len(hooks))
	closeAttached := func() error {
		b.programs = programs
		b.links = links
		return b.closeHooks()
	}
	for _, hook := range hooks {
		program, err := newSelfBypassSocketAddrProgram(b.sockets.FD(), hook, ownerTGID, storageFD)
		if err != nil {
			return E.Errors(err, closeAttached())
		}
		programs = append(programs, program)
		programLink, err := attachCgroupProgram(path, program, hook.attachType)
		if err != nil {
			return E.Errors(E.Cause(err, "attach eBPF self-bypass ", hook.hookName, " hook"), closeAttached())
		}
		links = append(links, programLink)
	}
	b.programs = programs
	b.links = links
	return nil
}

type selfBypassSocketAddrHook struct {
	hookName          string
	kernelProgramName string
	attachType        CiliumEBPF.AttachType
}

func selfBypassSocketAddrHooks(config SelfBypassCgroupConfig) []selfBypassSocketAddrHook {
	hooks := make([]selfBypassSocketAddrHook, 0, 4)
	if config.EnableTCP {
		hooks = append(hooks, selfBypassSocketAddrHook{"connect4", kernelProgramNameSelfConnect4, CiliumEBPF.AttachCGroupInet4Connect})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"connect6", kernelProgramNameSelfConnect6, CiliumEBPF.AttachCGroupInet6Connect})
		}
	}
	if config.EnableUDP {
		hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg4", kernelProgramNameSelfSendmsg4, CiliumEBPF.AttachCGroupUDP4Sendmsg})
		if config.EnableIPv6 {
			hooks = append(hooks, selfBypassSocketAddrHook{"sendmsg6", kernelProgramNameSelfSendmsg6, CiliumEBPF.AttachCGroupUDP6Sendmsg})
		}
	}
	return hooks
}

func newSelfBypassCreateProgram(mapFD int, ownerTGID uint32, storageFD ...int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameSelfCreate,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: selfBypassCreateInstructions(mapFD, ownerTGID, storageFD...),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-create hook")
	}
	return program, nil
}

func newSelfBypassReleaseProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         kernelProgramNameSelfRelease,
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
		License:      "GPL",
		Instructions: selfBypassReleaseInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-release hook")
	}
	return program, nil
}

func newSelfBypassSocketAddrProgram(mapFD int, hook selfBypassSocketAddrHook, ownerTGID uint32, storageFD ...int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         hook.kernelProgramName,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   hook.attachType,
		License:      "GPL",
		Instructions: selfBypassSocketAddrInstructions(mapFD, ownerTGID, storageFD...),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass ", hook.hookName, " hook")
	}
	return program, nil
}

// selfBypassOwnerCheckInstructions skips recording unless the current task
// belongs to ownerTGID. bpf_get_current_pid_tgid reports the thread-group id in
// the initial PID namespace, which selfBypassOwnerTGID guarantees equals
// os.Getpid. The context pointer is kept in R6 across the helper call and
// restored to R1 for the socket-cookie helper that follows.
func selfBypassOwnerCheckInstructions(ownerTGID uint32) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.JNE.Imm(asm.R0, int32(ownerTGID), "allow"),
		asm.Mov.Reg(asm.R1, asm.R6),
	}
}

func optionalSelfBypassStorageFD(storageFD []int) int {
	if len(storageFD) == 0 {
		return -1
	}
	return storageFD[0]
}

func selfBypassStorageMarkInstructions(storageFD int, socketAddr bool) asm.Instructions {
	if storageFD < 0 {
		return nil
	}
	instructions := asm.Instructions{asm.LoadMapPtr(asm.R1, storageFD)}
	if socketAddr {
		instructions = append(instructions,
			asm.LoadMem(asm.R2, asm.R6, bpfSockAddrSocketOffset, asm.DWord),
			asm.JEq.Imm(asm.R2, 0, "storage_done"),
		)
	} else {
		instructions = append(instructions, asm.Mov.Reg(asm.R2, asm.R6))
	}
	return append(instructions,
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Imm(asm.R4, 1), // BPF_LOCAL_STORAGE_GET_F_CREATE
		asm.FnSkStorageGet.Call(),
		asm.JEq.Imm(asm.R0, 0, "storage_done"),
		asm.StoreImm(asm.R0, 0, SocketMetadataSelfBypass, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("storage_done"),
	)
}

func selfBypassCreateInstructions(mapFD int, ownerTGID uint32, storageFD ...int) asm.Instructions {
	instructions := selfBypassOwnerCheckInstructions(ownerTGID)
	instructions = append(instructions, selfBypassStorageMarkInstructions(optionalSelfBypassStorageFD(storageFD), false)...)
	return append(instructions,
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, -12, 1, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
}

func selfBypassReleaseInstructions(mapFD int) asm.Instructions {
	return socketCookieDeleteInstructions(mapFD)
}

func socketCookieDeleteInstructions(mapFDs ...int) asm.Instructions {
	instructions := asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
	}
	for _, mapFD := range mapFDs {
		if mapFD < 0 {
			continue
		}
		// Maps can evict independently. A missing entry in one must not skip
		// cleanup of the same cookie in the others.
		instructions = append(instructions,
			asm.LoadMapPtr(asm.R1, mapFD),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.FnMapDeleteElem.Call(),
		)
	}
	return append(instructions,
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
}

func selfBypassSocketAddrInstructions(mapFD int, ownerTGID uint32, storageFD ...int) asm.Instructions {
	instructions := selfBypassOwnerCheckInstructions(ownerTGID)
	instructions = append(instructions, selfBypassStorageMarkInstructions(optionalSelfBypassStorageFD(storageFD), true)...)
	return append(instructions,
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "mark"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.And.Imm(asm.R5, SocketMetadataSelfBypass),
		asm.JNE.Imm(asm.R5, 0, "allow"),
		asm.Or.Imm(asm.R0, SocketMetadataSelfBypass),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.Ja.Label("update"),
		asm.StoreImm(asm.RFP, -12, SocketMetadataSelfBypass, asm.Word).WithSymbol("mark"),
		asm.LoadMapPtr(asm.R1, mapFD).WithSymbol("update"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
}

// SocketCookie returns the stable kernel cookie of a live socket.
func (b *SelfBypass) SocketCookie(rawConn syscall.RawConn) (uint64, error) {
	var cookie uint64
	err := control.Raw(rawConn, func(fd uintptr) error {
		var err error
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	})
	if err != nil {
		return 0, err
	}
	if cookie == 0 {
		return 0, E.New("socket returned an empty eBPF self-bypass cookie")
	}
	return cookie, nil
}

// registerSocket records a socket and returns a lifecycle token. The token can
// be retained by a dial attempt and released after a failed connect, when the
// original file descriptor has already been closed by net.Dialer.
func (b *SelfBypass) registerSocket(rawConn syscall.RawConn) (SocketRegistration, error) {
	if b == nil {
		return SocketRegistration{}, nil
	}
	b.access.RLock()
	if b.sockets == nil && !b.closed {
		// First registration before any data plane prepared the map. Create
		// it now so the socket is still excluded once interception starts;
		// a failure fails the socket rather than leaving it unregistered.
		b.access.RUnlock()
		if _, err := b.PreparedMap(); err != nil && !errors.Is(err, errSelfBypassClosed) {
			return SocketRegistration{}, err
		}
		b.access.RLock()
	}
	defer b.access.RUnlock()
	if b.sockets == nil {
		return SocketRegistration{}, nil
	}
	value := uint32(SocketMetadataSelfBypass)
	if b.storageActive && b.storage != nil {
		storageErr := control.Raw(rawConn, func(fd uintptr) error {
			key := int32(fd)
			return b.storage.Update(&key, &value, CiliumEBPF.UpdateAny)
		})
		if storageErr == nil {
			// Address-hook mode without sock_release still owns a cookie shadow.
			// Return its token so failed dial attempts can remove that shadow even
			// though the primary socket-local publication succeeded.
			if b.storageProducer && b.NeedsUserspaceUnregister() {
				cookie, cookieErr := b.SocketCookie(rawConn)
				if cookieErr != nil {
					return SocketRegistration{}, E.Cause(cookieErr, "read socket cookie for eBPF self-bypass cleanup")
				}
				return SocketRegistration{Cookie: cookie}, nil
			}
			return SocketRegistration{}, nil
		}
		b.storageWriteFails.Add(1)
		b.cookieFallbacks.Add(1)
	}
	cookie, err := b.SocketCookie(rawConn)
	if err != nil {
		return SocketRegistration{}, E.Cause(err, "read socket cookie for eBPF self-bypass")
	}
	err = b.sockets.Update(&cookie, &value, CiliumEBPF.UpdateAny)
	if errors.Is(err, unix.E2BIG) {
		b.reclaimAttempts.Add(1)
		b.reclaimLastAt.Store(time.Now().UnixNano())
		reclaimed, reclaimErr := b.reclaimClosedSockets()
		b.reclaimedSockets.Add(uint64(reclaimed))
		if reclaimErr != nil {
			b.reclaimFailures.Add(1)
		}
		if reclaimed > 0 {
			err = b.sockets.Update(&cookie, &value, CiliumEBPF.UpdateAny)
		}
	}
	if err != nil {
		return SocketRegistration{}, E.Cause(err, "register eBPF self-bypass socket")
	}
	return SocketRegistration{Cookie: cookie}, nil
}

// reclaimClosedSockets removes self-bypass entries whose socket is no longer
// open in this process. It runs only after a map-full update failure, so the
// normal registration path remains one cookie read and one map update.
// Process-tracker policy entries are deliberately left untouched.
func (b *SelfBypass) reclaimClosedSockets() (int, error) {
	var (
		cookie    uint64
		metadata  uint32
		candidate []uint64
	)
	entries := b.sockets.Iterate()
	for entries.Next(&cookie, &metadata) {
		if metadata&SocketMetadataSelfBypass != 0 {
			candidate = append(candidate, cookie)
		}
	}
	if entries.Err() != nil || len(candidate) == 0 {
		return 0, entries.Err()
	}
	open, err := openSocketCookies()
	if err != nil {
		return 0, err
	}
	var (
		reclaimed int
		deleteErr error
	)
	for _, cookie := range candidate {
		if _, loaded := open[cookie]; loaded {
			continue
		}
		if err = b.sockets.Delete(&cookie); err == nil || errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			if err == nil {
				reclaimed++
			}
		} else {
			deleteErr = errors.Join(deleteErr, err)
		}
	}
	return reclaimed, deleteErr
}

// openSocketCookies returns cookies for all sockets currently open in this
// process. A descriptor reused during the scan can only add a live cookie,
// which is safe to retain.
func openSocketCookies() (map[uint64]struct{}, error) {
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	open := make(map[uint64]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		fd, err := strconv.Atoi(descriptor.Name())
		if err != nil {
			continue
		}
		if cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE); err == nil && cookie != 0 {
			open[cookie] = struct{}{}
		}
	}
	return open, nil
}

// RegisterSocket publishes a socket only when the selected producer requires
// userspace control. The returned token owns any required userspace cleanup.
func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) (SocketRegistration, error) {
	if b == nil || !b.NeedsUserspaceRegistration() {
		return SocketRegistration{}, nil
	}
	return b.registerSocket(rawConn)
}

// UnregisterSocket releases a token returned by RegisterSocket. Deletion is
// idempotent because a kernel release hook may already have removed the same
// cookie on a fallback path.
func (b *SelfBypass) UnregisterSocket(registration SocketRegistration) error {
	if b == nil || !registration.Active() || !b.NeedsUserspaceUnregister() {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil {
		return nil
	}
	if err := b.sockets.Delete(&registration.Cookie); err != nil {
		if errors.Is(err, CiliumEBPF.ErrKeyNotExist) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return E.Cause(err, "unregister eBPF self-bypass socket")
	}
	return nil
}

// selfBypassProbePort is the discard port used by the socket-address probe.
// The probe only connects a UDP socket or sends an empty datagram to loopback.
const selfBypassProbePort = 9

// selfBypassOwner resolves the metadata owner; tests replace it to force the
// post-attach probe to fail.
var selfBypassOwner = selfBypassOwnerTGID

// selfBypassOwnerTGID returns the thread-group id the metadata hooks compare
// against. bpf_get_current_pid_tgid returns the kernel (initial namespace) TGID.
// NSpid exposes that value as its first field when the process is in a nested
// PID namespace; kernels without PID namespace support omit the field and use
// os.Getpid().
// This avoids depending on /proc/*/ns/pid, which Android kernels may omit even
// for a process that can otherwise use cgroup BPF.
func selfBypassOwnerTGID() (uint32, error) {
	pid := os.Getpid()
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "NSpid:") {
				continue
			}
			fields := strings.Fields(line[len("NSpid:"):])
			if len(fields) > 0 {
				parsed, parseErr := strconv.Atoi(fields[0])
				if parseErr != nil {
					return 0, E.Cause(parseErr, "parse process kernel TGID")
				}
				pid = parsed
			}
			break
		}
	}
	if pid <= 0 || pid > math.MaxInt32 {
		return 0, E.New("process id out of range: ", pid)
	}
	return uint32(pid), nil
}

// verifyOwnerMetadata checks on the running kernel that every requested hook
// writes self-bypass metadata for a socket owned by this process. In cgroup
// mode the consumer stops registering sockets itself, so a partially working
// hook set must not be reported as active.
func (b *SelfBypass) verifyOwnerMetadata(socketAddr bool, config SelfBypassCgroupConfig, storage ...bool) error {
	storageEnabled := len(storage) > 0 && storage[0]
	if socketAddr {
		if !config.EnableTCP && !config.EnableUDP {
			return E.New("eBPF self-bypass socket-address hooks have no enabled protocol")
		}
		if config.EnableTCP {
			if err := b.verifyOwnerSocketAddr(unix.AF_INET, unix.SOCK_STREAM, false, "TCP IPv4 connect", storageEnabled); err != nil {
				return err
			}
			if config.EnableIPv6 {
				if err := b.verifyOwnerSocketAddr(unix.AF_INET6, unix.SOCK_STREAM, true, "TCP IPv6 connect", storageEnabled); err != nil {
					return err
				}
			}
		}
		if config.EnableUDP {
			if err := b.verifyOwnerSocketAddr(unix.AF_INET, unix.SOCK_DGRAM, false, "UDP IPv4 sendmsg", storageEnabled); err != nil {
				return err
			}
			if config.EnableIPv6 {
				if err := b.verifyOwnerSocketAddr(unix.AF_INET6, unix.SOCK_DGRAM, true, "UDP IPv6 sendmsg", storageEnabled); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := b.verifyOwnerSocketCreate(unix.AF_INET, "socket-create IPv4", storageEnabled); err != nil {
		return err
	}
	if config.EnableIPv6 {
		if err := b.verifyOwnerSocketCreate(unix.AF_INET6, "socket-create IPv6", storageEnabled); err != nil {
			return err
		}
	}
	return nil
}

func (b *SelfBypass) verifyOwnerSocketCreate(family int, label string, storage bool) error {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return E.Cause(err, "create eBPF self-bypass ", label, " probe socket")
	}
	defer unix.Close(fd)
	return b.verifyOwnerSocketMetadata(fd, label, storage)
}

func (b *SelfBypass) verifyOwnerSocketAddr(family, socketType int, ipv6 bool, label string, storage bool) error {
	fd, err := unix.Socket(family, socketType|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return E.Cause(err, "create eBPF self-bypass ", label, " probe socket")
	}
	defer unix.Close(fd)
	if ipv6 {
		address := &unix.SockaddrInet6{Port: selfBypassProbePort, Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
		if err = unix.Connect(fd, address); err != nil && !errors.Is(err, unix.ECONNREFUSED) {
			return E.Cause(err, "trigger eBPF self-bypass ", label, " hook")
		}
	} else {
		address := &unix.SockaddrInet4{Port: selfBypassProbePort, Addr: [4]byte{127, 0, 0, 1}}
		if socketType == unix.SOCK_STREAM {
			if err = unix.Connect(fd, address); err != nil && !errors.Is(err, unix.ECONNREFUSED) {
				return E.Cause(err, "trigger eBPF self-bypass ", label, " hook")
			}
		} else if err = unix.Sendto(fd, nil, 0, address); err != nil && !errors.Is(err, unix.ECONNREFUSED) {
			return E.Cause(err, "trigger eBPF self-bypass ", label, " hook")
		}
	}
	return b.verifyOwnerSocketMetadata(fd, label, storage)
}

func (b *SelfBypass) verifyOwnerSocketMetadata(fd int, label string, storage bool) error {
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return E.Cause(err, "read eBPF self-bypass ", label, " probe socket cookie")
	}
	var metadata uint32
	lookupErr := b.sockets.Lookup(&cookie, &metadata)
	_ = b.sockets.Delete(&cookie)
	if lookupErr != nil || metadata&SocketMetadataSelfBypass == 0 {
		return E.New("eBPF self-bypass ", label, " hook did not mark a socket of this process")
	}
	if storage {
		metadata = 0
		storageKey := int32(fd)
		if b.storage == nil || b.storage.Lookup(&storageKey, &metadata) != nil || metadata&SocketMetadataSelfBypass == 0 {
			return E.New("eBPF self-bypass ", label, " hook did not publish socket-local metadata")
		}
	}
	return nil
}

func processCgroupExclusive(path string) (bool, error) {
	pid := os.Getpid()
	found, exclusive, err := readExclusiveCgroupMembers(path, pid)
	if err != nil || !exclusive || !found {
		return found && exclusive, err
	}
	return inspectExclusiveCgroupDescendants(path)
}

func readExclusiveCgroupMembers(path string, pid int) (found bool, exclusive bool, err error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		member, parseErr := strconv.Atoi(line)
		if parseErr != nil {
			return false, false, E.Cause(parseErr, "parse process cgroup member")
		}
		if member != pid {
			return found, false, nil
		}
		found = true
	}
	if err = scanner.Err(); err != nil {
		return false, false, E.Cause(err, "read process cgroup members")
	}
	return found, true, nil
}

func inspectExclusiveCgroupDescendants(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, E.Cause(err, "read process cgroup children")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childPath := filepath.Join(path, entry.Name())
		populated, childErr := cgroupHasMembers(childPath)
		if childErr != nil {
			return false, childErr
		}
		if populated {
			return false, nil
		}
		childExclusive, childErr := inspectExclusiveCgroupDescendants(childPath)
		if childErr != nil || !childExclusive {
			return false, childErr
		}
	}
	return true, nil
}

func cgroupHasMembers(path string) (bool, error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			return true, nil
		}
	}
	if err = scanner.Err(); err != nil {
		return false, E.Cause(err, "read child cgroup members")
	}
	return false, nil
}

func (b *SelfBypass) closeHooks() error {
	if b == nil {
		return nil
	}
	var closeErr error
	linksClosed := true
	for index := len(b.links) - 1; index >= 0; index-- {
		if b.links[index] != nil {
			linkErr := b.links[index].Close()
			closeErr = E.Errors(closeErr, linkErr)
			if cgroupProgramLinkCloseComplete(b.links[index], linkErr) {
				b.links[index] = nil
			} else {
				linksClosed = false
			}
		}
	}
	if !linksClosed {
		return closeErr
	}
	for index := len(b.programs) - 1; index >= 0; index-- {
		if b.programs[index] != nil {
			closeErr = E.Errors(closeErr, b.programs[index].Close())
			b.programs[index] = nil
		}
	}
	b.links = nil
	b.programs = nil
	b.mode.Store(uint32(SelfBypassUserspace))
	b.decisionBackend = selfBypassDecisionUserspace
	b.producerBackend = selfBypassProducerUserspace
	b.visibilityBackend = selfBypassVisibilityCookieHash
	b.cleanupBackend = selfBypassCleanupUserspace
	b.reclaimBackend = selfBypassReclaimProcFD
	b.attachmentBackend = "none"
	b.directTGID = 0
	b.directFallback = SelfBypassCgroupConfig{}
	b.storageProducer = false
	return closeErr
}

func (b *SelfBypass) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	// No new map may be created once closing has begun, even if hooks must
	// be retried.
	b.closed = true
	closeErr := b.closeHooks()
	if lenOpenCgroupProgramLinks(b.links) > 0 {
		return closeErr
	}
	closeErr = E.Errors(closeErr, b.closeStorageLocked())
	b.storageActive = false
	if b.sockets != nil {
		closeErr = E.Errors(closeErr, b.sockets.Close())
		b.sockets = nil
	}
	return closeErr
}

func (b *SelfBypass) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.closed && b.sockets == nil && b.storage == nil && lenOpenCgroupProgramLinks(b.links) == 0
}
