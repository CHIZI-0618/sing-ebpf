//go:build with_ebpf && (linux || android)

package core

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type cgroupProgramLink interface {
	Close() error
}

type retryableCgroupProgramLink interface {
	cgroupProgramLink
	IsClosed() bool
}

func cgroupProgramLinkMechanism(programLink cgroupProgramLink) string {
	if _, legacy := programLink.(*legacyCgroupProgramLink); legacy {
		return "legacy_attach"
	}
	return "bpf_link"
}

// cgroupProgramLinkCloseComplete distinguishes a failed legacy detach, whose
// target FD must be retained for another attempt, from link.Close errors where
// the link FD has already been consumed and cannot be retried safely.
func cgroupProgramLinkCloseComplete(programLink cgroupProgramLink, closeErr error) bool {
	if closeErr == nil {
		return true
	}
	retryableLink, retryable := programLink.(retryableCgroupProgramLink)
	return !retryable || retryableLink.IsClosed()
}

// attachRawLink is replaced in tests to exercise the legacy fallbacks without
// a kernel that rejects BPF_LINK_CREATE.
var attachRawLink = link.AttachRawLink

// cgroupAttachPolicy selects whether a legacy cgroup attachment may end in
// the kernel's single-program mode.
type cgroupAttachPolicy uint8

const (
	// cgroupAttachAllowExclusive permits the unflagged legacy fallback on an
	// empty hook when the kernel rejects multi-program attachment. Use it only
	// for a component that owns its cgroup or has no other fallback.
	cgroupAttachAllowExclusive cgroupAttachPolicy = iota
	// cgroupAttachMultiOnly never leaves the hook in single-program mode. A
	// single-program hook makes the kernel reject every later multi-program
	// attachment, including BPF_LINK_CREATE, so an optional component that
	// shares a cgroup with the interception backend must not create one.
	cgroupAttachMultiOnly
)

// attachCgroupProgram prefers BPF_LINK_CREATE, whose cgroup implementation is
// inherently multi-program, then falls back to legacy BPF_PROG_ATTACH. The
// legacy path tries BPF_F_ALLOW_MULTI first and retries without flags only when
// the kernel rejects multi attachment with a compatibility error and the hook
// is empty.
func attachCgroupProgram(path string, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) (cgroupProgramLink, error) {
	return attachCgroupProgramWithPolicy(path, program, attachType, cgroupAttachAllowExclusive)
}

// attachCgroupProgramShared attaches an optional program to a cgroup that may
// also carry the interception backend. It uses only multi-program operations,
// so a kernel that rejects them makes the optional feature unavailable instead
// of locking the required backend out of the same hook.
func attachCgroupProgramShared(path string, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) (cgroupProgramLink, error) {
	return attachCgroupProgramWithPolicy(path, program, attachType, cgroupAttachMultiOnly)
}

func attachCgroupProgramWithPolicy(
	path string,
	program *CiliumEBPF.Program,
	attachType CiliumEBPF.AttachType,
	policy cgroupAttachPolicy,
) (cgroupProgramLink, error) {
	cgroupFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	programLink, linkErr := attachRawLink(link.RawLinkOptions{
		Target:  int(cgroupFile.Fd()),
		Program: program,
		Attach:  attachType,
	})
	if linkErr == nil {
		_ = cgroupFile.Close()
		return programLink, nil
	}
	if !cgroupLinkUnavailable(linkErr) {
		_ = cgroupFile.Close()
		return nil, linkErr
	}
	if policy == cgroupAttachMultiOnly {
		err = attachProgramRawMultiOnly(int(cgroupFile.Fd()), program, attachType)
	} else {
		err = attachProgramRaw(int(cgroupFile.Fd()), program, attachType)
	}
	if err != nil {
		_ = cgroupFile.Close()
		return nil, E.Errors(linkErr, err)
	}
	return &legacyCgroupProgramLink{
		cgroupFile: cgroupFile,
		program:    program,
		attachType: attachType,
	}, nil
}

type legacyCgroupProgramLink struct {
	cgroupFile *os.File
	program    *CiliumEBPF.Program
	attachType CiliumEBPF.AttachType
	// detachProgram is nil in production. Tests inject a transient detach
	// failure to prove that the target FD remains owned for a cleanup retry.
	detachProgram func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error
}

func (l *legacyCgroupProgramLink) Close() error {
	if l == nil || l.cgroupFile == nil {
		return nil
	}
	detachProgram := l.detachProgram
	if detachProgram == nil {
		detachProgram = rawDetachProgram
	}
	detachErr := detachProgram(int(l.cgroupFile.Fd()), l.program, l.attachType)
	if detachErr != nil && !errors.Is(detachErr, unix.ENOENT) && !errors.Is(detachErr, unix.ESRCH) {
		return detachErr
	}
	closeErr := l.cgroupFile.Close()
	l.cgroupFile = nil
	return closeErr
}

func (l *legacyCgroupProgramLink) IsClosed() bool {
	return l == nil || l.cgroupFile == nil
}

// cgroupSharedLockTimeout bounds the wait for another backend's exclusive
// startup reclaim to finish.
var cgroupSharedLockTimeout = 2 * time.Second

// lockCgroupFile marks the cgroup as managed by an interception backend and
// reports whether this backend is the only one alive on it.
//
// Every backend of this build keeps a shared lock on the cgroup directory for
// its lifetime, so several backends can run on one cgroup. Builds without
// multi-instance support keep an exclusive lock instead, which keeps them and
// this build off the same cgroup. A backend starts by taking the lock
// exclusively: getting it proves that no other backend is alive on the cgroup,
// so every interception program found there is stale and may be reclaimed.
// shareCgroupLock then downgrades it before anything is attached.
//
// A lock that stays held exclusively is reported as EBUSY, so callers matching
// on it keep working, but it is described for what is known rather than what is
// likely: the holder may be a running instance of such a build or a handle one
// kept after a close that did not finish.
func lockCgroupFile(cgroupFile *os.File) (bool, error) {
	err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return false, eBPFOperationError("lock cgroup", err)
	}
	return false, shareCgroupLock(cgroupFile)
}

// shareCgroupLock takes or downgrades to the shared lock. An exclusive holder of
// this build only keeps it while it reclaims stale programs.
func shareCgroupLock(cgroupFile *os.File) error {
	deadline := time.Now().Add(cgroupSharedLockTimeout)
	for {
		err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return eBPFOperationError("lock cgroup", err)
		}
		if !time.Now().Before(deadline) {
			return E.Cause(unix.EBUSY,
				"the exclusive lock on this cgroup is already held, "+
					"either by an active instance of a sing-ebpf build without multi-instance support "+
					"or by an earlier close of one that did not finish: ",
				"lock cgroup")
		}
		time.Sleep(instanceMutexRetry)
	}
}

// acquireCgroupSlot takes one of the cgroup's instance slots. The slot keys
// the kernel names of this backend's programs, which is what lets a backend
// that shares the cgroup with others reclaim the stale programs of its own
// slot and only those. Slot names live in the caller's network namespace, as
// do the redirect routes a backend depends on, so backends sharing a cgroup are
// expected to share one.
func acquireCgroupSlot(cgroupFile *os.File) (*InstanceSlot, error) {
	var status unix.Stat_t
	if err := unix.Fstat(int(cgroupFile.Fd()), &status); err != nil {
		return nil, eBPFOperationError("inspect cgroup", err)
	}
	base := "@sing-ebpf-cgroup-" + strconv.FormatUint(uint64(status.Dev), 16) + "-" + strconv.FormatUint(status.Ino, 16)
	slot, err := AcquireInstanceSlot(func(slot int) string { return InstanceSlotName(base, slot) })
	if errors.Is(err, ErrInstanceSlotsExhausted) {
		return nil, E.New("cgroup is already managed by ", MaxInstanceSlots, " sing-ebpf interception backends")
	}
	if err != nil {
		return nil, E.Cause(err, "lock cgroup slot")
	}
	return slot, nil
}

// Reclaim scopes for detachOwnedCgroupPrograms besides a slot number.
const (
	// cgroupReclaimAllSlots reclaims every interception program: no other
	// backend is alive on the cgroup.
	cgroupReclaimAllSlots = -1
	// cgroupReclaimNoSlot reclaims no interception program: a backend in
	// another network namespace may hold the same slot number.
	cgroupReclaimNoSlot = -2
)

// procLocksPath is a variable so tests can supply a listing.
var procLocksPath = "/proc/locks"

// cgroupSharedAcrossNetworkNamespaces reports whether a process in another
// network namespace holds a lock on the cgroup. Slot names are abstract socket
// names, which that namespace does not see, so a backend there may hold the
// same slot number as this one and reclaiming "this slot's" programs could
// detach its live ones. A listing that cannot be read reports false: the
// namespaces are then assumed to be shared, as backends are expected to be.
func cgroupSharedAcrossNetworkNamespaces(cgroupFile *os.File) bool {
	var status unix.Stat_t
	if err := unix.Fstat(int(cgroupFile.Fd()), &status); err != nil {
		return false
	}
	own, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		if own, err = os.Readlink("/proc/self/ns/net"); err != nil {
			return false
		}
	}
	locks, err := os.Open(procLocksPath)
	if err != nil {
		return false
	}
	defer locks.Close()
	file := fmt.Sprintf("%02x:%02x:%d", unix.Major(uint64(status.Dev)), unix.Minor(uint64(status.Dev)), status.Ino)
	return foreignNetworkNamespaceLockHolder(locks, file, os.Getpid(), own, func(pid int) (string, error) {
		return os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net")
	})
}

// foreignNetworkNamespaceLockHolder scans a /proc/locks listing for a flock
// on file held by a process whose network namespace differs from own. A
// holder whose namespace cannot be read counts as foreign unless it has
// exited.
func foreignNetworkNamespaceLockHolder(
	locks io.Reader,
	file string,
	ownPID int,
	own string,
	networkNamespace func(pid int) (string, error),
) bool {
	scanner := bufio.NewScanner(locks)
	for scanner.Scan() {
		// "1: FLOCK  ADVISORY  READ 1234 00:1d:5678 0 EOF", with "->" after
		// the number for a waiter.
		fields := strings.Fields(scanner.Text())
		index := slices.Index(fields, "FLOCK")
		if index < 0 || len(fields) < index+5 || fields[index+4] != file {
			continue
		}
		pid, err := strconv.Atoi(fields[index+3])
		if err != nil || pid <= 0 || pid == ownPID {
			continue
		}
		namespace, err := networkNamespace(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || namespace != own {
			return true
		}
	}
	return false
}

// cgroupKernelProgramName is the kernel name of an interception program in a
// cgroup slot. Slot 0 keeps the names of single-instance builds, so the stale
// programs such a build leaves behind are slot 0's.
func cgroupKernelProgramName(base string, slot int) string {
	if slot == 0 {
		return base
	}
	return base + "_" + strconv.FormatUint(uint64(slot), 16)
}

// cgroupProgramSlot returns the slot an interception program name belongs to,
// or -1 for any other name. The sing_ebpf_ programs of older releases come
// from single-instance builds, whose leftovers are slot 0's.
func cgroupProgramSlot(name string) int {
	if strings.HasPrefix(name, kernelProgramPrefixLegacyCgroup) {
		return 0
	}
	for _, definition := range cgroupProgramDefinitions {
		if name == definition.kernelProgramName {
			return 0
		}
		suffix, found := strings.CutPrefix(name, definition.kernelProgramName+"_")
		if !found || len(suffix) != 1 {
			continue
		}
		slot, err := strconv.ParseUint(suffix, 16, 8)
		if err == nil && slot > 0 && slot < MaxInstanceSlots {
			return int(slot)
		}
	}
	return -1
}

// cgroupProgQueryAttr is the BPF_PROG_QUERY member of union bpf_attr, through
// query.revision. It must not be shortened: Linux 6.17 and 6.18 write
// query.revision back to offset 56 whatever attribute size the caller passes,
// so a shorter attribute lets the kernel write past it (fixed upstream by
// "bpf: fix BPF_PROG_QUERY OOB write and cgroup backward compat"). The layout
// matches cilium/ebpf's sys.ProgQueryAttr.
type cgroupProgQueryAttr struct {
	targetFD           uint32
	attachType         uint32
	queryFlags         uint32
	attachFlags        uint32
	programIDs         uint64
	programs           uint32
	_                  uint32
	programAttachFlags uint64
	linkIDs            uint64
	linkAttachFlags    uint64
	revision           uint64
}

// queryCgroupHookFlags returns the attach mode the kernel recorded for a
// cgroup hook (0, BPF_F_ALLOW_OVERRIDE or BPF_F_ALLOW_MULTI). cilium/ebpf's
// QueryPrograms does not expose this field, so the request is issued directly;
// with prog_cnt = 0 every kernel since BPF_PROG_QUERY was introduced returns
// only the count and the flags.
var queryCgroupHookFlags = func(cgroupFD int, attachType CiliumEBPF.AttachType) (uint32, error) {
	attr := cgroupProgQueryAttr{
		targetFD:   uint32(cgroupFD),
		attachType: uint32(attachType),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.attachFlags, nil
}

// reclaimableCgroupProgram decides which programs found on the interception
// cgroup at startup are stale sing-ebpf state that may be detached.
//
// slot is cgroupReclaimAllSlots when the backend holds the cgroup lock
// exclusively: no other interception backend is alive, so every interception
// program is stale. Otherwise other backends share the cgroup and only the
// programs named for the backend's own slot are stale, since the slot is held,
// and cgroupReclaimNoSlot reclaims none of them. Programs attached through a
// BPF link disappear with their owner and are never found stale; a legacy
// detach does not reach them either.
//
// A process tracker program is reclaimed only when it is the single program of
// a hook that is not in multi-program mode. The tracker attaches with
// multi-program operations only, and BPF links are always multi-program, so
// such an attachment can only come from an unflagged legacy BPF_PROG_ATTACH
// made by an earlier sing-ebpf build. That attachment belongs to the cgroup,
// survives its process, and makes the kernel reject every multi-program
// attachment on the hook. A tracker attached by a live process in multi mode,
// including one this process started before the backend, is left alone.
func reclaimableCgroupProgram(name string, slot int, hookFlags uint32, programCount int) bool {
	if ownedCgroupProgramName(name) {
		return slot == cgroupReclaimAllSlots || slot >= 0 && cgroupProgramSlot(name) == slot
	}
	return strings.HasPrefix(name, kernelProgramPrefixProcessTracker) &&
		hookFlags&unix.BPF_F_ALLOW_MULTI == 0 && programCount == 1
}

// detachOwnedCgroupPrograms reclaims the stale programs reclaimableCgroupProgram
// selects for slot.
func detachOwnedCgroupPrograms(cgroupFD int, slot int) error {
	for _, definition := range cgroupProgramDefinitions {
		first, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease && socketReleaseUnavailable(err) {
				continue
			}
			if (definition.attachType == CiliumEBPF.AttachCgroupInet4GetPeername ||
				definition.attachType == CiliumEBPF.AttachCgroupInet6GetPeername) && getpeernameUnavailable(err) {
				continue
			}
			return err
		}
		if len(first) == 0 {
			continue
		}
		// Unknown flags are treated as multi-program mode so that only
		// interception backend programs are reclaimed.
		hookFlags := uint32(unix.BPF_F_ALLOW_MULTI)
		if flags, flagsErr := queryCgroupHookFlags(cgroupFD, definition.attachType); flagsErr == nil {
			hookFlags = flags
		}
		second, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			return err
		}
		if !sameProgramIDs(first, second) {
			return unix.ESTALE
		}
		for _, programID := range first {
			program, openErr := CiliumEBPF.NewProgramFromID(programID)
			if openErr != nil {
				return openErr
			}
			info, infoErr := program.Info()
			if infoErr != nil {
				_ = program.Close()
				return infoErr
			}
			if reclaimableCgroupProgram(info.Name, slot, hookFlags, len(first)) {
				// A stale program that is the sole single-program owner took the
				// hook over from Android netd and never gave it back. Put a netd
				// placeholder back instead of emptying the hook; the ordinary
				// attach then takes the hook over again and restores it on
				// detach.
				if hookFlags&unix.BPF_F_ALLOW_MULTI == 0 && len(first) == 1 {
					restored, restoreErr := restoreNetdOwnerForStaleProgram(cgroupFD, definition.attachType, hookFlags)
					if restoreErr != nil {
						_ = program.Close()
						return restoreErr
					}
					if restored {
						if closeErr := program.Close(); closeErr != nil {
							return closeErr
						}
						continue
					}
				}
				// ENOENT: the program is attached through a link, so its owner is
				// alive and only it can detach the program.
				if detachErr := rawDetachProgram(cgroupFD, program, definition.attachType); detachErr != nil &&
					!errors.Is(detachErr, unix.ENOENT) {
					_ = program.Close()
					return detachErr
				}
			}
			if closeErr := program.Close(); closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

// ownedCgroupProgramName reports whether name is an interception program of
// any sing-ebpf generation. Older releases used the sing_ebpf_ prefix, the
// current names use sb_ebpf_. Unknown owners, such as netd's, never match.
func ownedCgroupProgramName(name string) bool {
	return strings.HasPrefix(name, kernelProgramPrefixCgroup) || strings.HasPrefix(name, kernelProgramPrefixLegacyCgroup)
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := queryCgroupPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	attachOrder := make([]int, 0, cgroupProgramCount)
	if b.runtime.programs[cgroupProgramSocketRelease] != nil {
		attachOrder = append(attachOrder, cgroupProgramSocketRelease)
	}
	for slot := range b.runtime.programs {
		if slot != cgroupProgramSocketRelease {
			attachOrder = append(attachOrder, slot)
		}
	}
	for _, slot := range attachOrder {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programLink, err := attachRawLink(link.RawLinkOptions{
			Target:  cgroupFD,
			Program: program,
			Attach:  cgroupProgramDefinitions[slot].attachType,
		})
		if err == nil {
			b.runtime.links[slot] = programLink
			b.runtime.attach_modes[slot] = cgroupAttachModeLinkCreate
		} else if cgroupLinkUnavailable(err) {
			var attachment legacyCgroupAttachment
			attachment, err = attachProgramRawWithMode(cgroupFD, program, cgroupProgramDefinitions[slot].attachType, true)
			if err == nil {
				b.runtime.attach_modes[slot] = attachment.mode
				b.runtime.displaced[slot] = attachment.displaced
			}
		}
		if err != nil && cgroupGetpeernameSlot(slot) && getpeernameUnavailable(err) {
			// Optional peer restoration; interception works without it.
			continue
		}
		if err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF cgroup programs", cgroupProgramDefinitions[slot].kernelProgramName, err)
		}
		b.runtime.attached[slot] = true
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported &&
		!b.runtime.attached[cgroupProgramSocketRelease] {
		_ = b.detachProgramsLocked()
		return eBPFOperationError("attach eBPF cgroup UDP cleanup", unix.EINVAL)
	}
	return nil
}

func cgroupLinkUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		programLink := b.runtime.links[slot]
		var err error
		if programLink != nil {
			err = programLink.Close()
			b.runtime.links[slot] = nil
			b.runtime.attached[slot] = false
			b.runtime.attach_modes[slot] = ""
			if err != nil {
				detachErr = E.Errors(detachErr, err)
			}
			continue
		} else if displaced := b.runtime.displaced[slot]; displaced != nil {
			// Put the netd placeholder back in place of our program. A
			// failure keeps the displaced owner for a cleanup retry.
			err = restoreDisplacedCgroupOwner(cgroupFD, b.runtime.programs[slot], displaced, cgroupProgramDefinitions[slot].attachType)
			if err == nil {
				b.runtime.displaced[slot] = nil
			}
		} else {
			err = rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		}
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			b.runtime.attach_modes[slot] = ""
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}
