//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	BPFGen "github.com/CHIZI-0618/sing-ebpf/internal/bpfgen"
	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const bpfFlagNoPrealloc = 1

var rawAttachProgram = link.RawAttachProgram

var queryCgroupPrograms = link.QueryPrograms

// describeCgroupProgram names an attached program for diagnostics. Tests
// replace it because opening a program by ID requires a live kernel object.
var describeCgroupProgram = func(id CiliumEBPF.ProgramID) string {
	program, err := CiliumEBPF.NewProgramFromID(id)
	if err != nil {
		return fmt.Sprintf("id=%d", id)
	}
	defer program.Close()
	info, err := program.Info()
	if err != nil || info.Name == "" {
		return fmt.Sprintf("id=%d", id)
	}
	return fmt.Sprintf("id=%d name=%s", id, info.Name)
}

// ErrCgroupHookOccupied reports that a cgroup hook already holds a program in
// single-program (exclusive or override) mode. The kernel rejects every
// multi-program attachment on such a hook, including BPF_LINK_CREATE, and the
// only remaining operation would displace that program. sing-ebpf does that
// only for a pass-through owner, such as the placeholder Android 15+ netd
// keeps on the root socket-address hooks, and restores it on detach. Every
// other owner is kept, so callers must choose another data plane or free the
// hook.
var ErrCgroupHookOccupied = errors.New("refusing to replace existing cgroup program owner")

type cgroupHookOccupiedError struct {
	attachType CiliumEBPF.AttachType
	owners     []string
	// detail explains why a recognized owner was still not replaced.
	detail error
}

func (e *cgroupHookOccupiedError) Error() string {
	message := ErrCgroupHookOccupied.Error() + " on " + e.attachType.String()
	if len(e.owners) > 0 {
		message += " (" + strings.Join(e.owners, ", ") + ")"
	}
	if e.detail != nil {
		message += ": " + e.detail.Error()
	}
	return message
}

func (e *cgroupHookOccupiedError) Unwrap() error {
	return ErrCgroupHookOccupied
}

func (e *cgroupHookOccupiedError) Is(target error) bool {
	return target == ErrCgroupHookOccupied || e.detail != nil && errors.Is(e.detail, target)
}

func newCgroupHookOccupiedError(attachType CiliumEBPF.AttachType, programs []link.AttachedProgram, detail error) error {
	owners := make([]string, 0, len(programs))
	for _, program := range programs {
		owners = append(owners, describeCgroupProgram(program.ID))
	}
	return &cgroupHookOccupiedError{attachType: attachType, owners: owners, detail: detail}
}

var loadTC = BPFGen.LoadTC

var loadCgroup = BPFGen.LoadCgroup

var loadCgroupNoMark = BPFGen.LoadCgroupNoMark

var loadCgroupStorage = BPFGen.LoadCgroupStorage

var loadCgroupStorageNoMark = BPFGen.LoadCgroupStorageNoMark

var loadCgroupStorageCoarse = BPFGen.LoadCgroupStorageCoarse

var loadCgroupStorageCoarseNoMark = BPFGen.LoadCgroupStorageCoarseNoMark

var loadCgroupCoarse = BPFGen.LoadCgroupCoarse

var loadCgroupCoarseNoMark = BPFGen.LoadCgroupCoarseNoMark

var loadSharedNetwork = BPFGen.LoadSharedNetwork

var loadICMPEchoReply = BPFGen.LoadICMPEchoReply

// legacyCgroupAttachment describes a successful legacy BPF_PROG_ATTACH: the
// variant that succeeded and, for cgroupAttachModeNetdReplace, the program it
// displaced, which the owner of the attachment must restore on detach.
type legacyCgroupAttachment struct {
	mode      string
	displaced *displacedCgroupOwner
}

const (
	cgroupAttachModeLinkCreate      = "link_create"
	cgroupAttachModeLegacyMulti     = "legacy_multi"
	cgroupAttachModeLegacyExclusive = "legacy_exclusive"
	// cgroupAttachModeNetdReplace is an unflagged attach that replaced the
	// pass-through placeholder Android netd holds on the hook. The hook stays
	// in single-program mode and the placeholder returns on detach.
	cgroupAttachModeNetdReplace = "legacy_netd_replace"
)

// attachProgramRaw is the legacy attach of optional components. It never
// displaces an existing owner, not even a pass-through one: a program of
// theirs in netd's place would be an owner that does real work, which the
// interception backend would then have to refuse, while the component itself
// has a userspace fallback.
func attachProgramRaw(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	_, err := attachProgramRawWithMode(target, program, attachType, false)
	return err
}

// attachProgramRawMultiOnly is used for optional capability probes and for
// optional components that share a cgroup with the required interception
// backend. Neither may fall back to the unflagged legacy operation: that
// variant replaces an existing exclusive cgroup owner, and on an empty hook it
// leaves the hook in single-program mode, which then locks every later
// multi-program user (including the interception backend) out of it. A denied
// multi attach simply means that the optional capability is unavailable.
func attachProgramRawMultiOnly(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	return rawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: program,
		Attach:  attachType,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	})
}

// attachProgramRawWithMode reports the legacy attach variant that actually
// succeeded. The distinction is operationally important on Android: a
// vendor kernel can reject BPF_F_ALLOW_MULTI while still accepting the
// single-program legacy operation. Callers must expose the effective path,
// not merely the attempted fast path.
//
// replacePassThrough lets the attach replace a pass-through owner, such as the
// placeholder Android 15+ netd keeps on the root socket-address hooks (see
// cgroup_netd.go). Only the interception backend sets it: it has no fallback,
// and it restores the displaced owner on detach.
func attachProgramRawWithMode(
	target int,
	program *CiliumEBPF.Program,
	attachType CiliumEBPF.AttachType,
	replacePassThrough bool,
) (legacyCgroupAttachment, error) {
	options := link.RawAttachProgramOptions{
		Target:  target,
		Program: program,
		Attach:  attachType,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	}
	multiErr := rawAttachProgram(options)
	if multiErr == nil {
		return legacyCgroupAttachment{mode: cgroupAttachModeLegacyMulti}, nil
	}
	if !cgroupMultiAttachUnavailable(multiErr) {
		return legacyCgroupAttachment{}, multiErr
	}
	// An unflagged legacy attach replaces the current exclusive owner. The one
	// owner that is replaced is a pass-through, such as the placeholder
	// Android 15+ netd keeps on the root socket-address hooks, and only when
	// replacePassThrough is set; it is held open and restored on detach (see
	// cgroup_netd.go). Any owner that does real work is left alone. Optional
	// components fall back to userspace; the interception backend has no such
	// fallback and reports ErrCgroupHookOccupied, naming the current owners so
	// the operator can tell a foreign program from a stale one of ours.
	// Kernels without BPF_PROG_QUERY retain the historical fallback because
	// there is no safe way to distinguish an empty hook from an unqueryable
	// one.
	if result, queryErr := queryCgroupPrograms(link.QueryOptions{Target: target, Attach: attachType}); queryErr == nil && len(result.Programs) > 0 {
		if !replacePassThrough {
			return legacyCgroupAttachment{}, newCgroupHookOccupiedError(attachType, result.Programs, nil)
		}
		displaced, keptReason := displaceableCgroupOwner(target, attachType, result.Programs)
		if displaced == nil {
			return legacyCgroupAttachment{}, newCgroupHookOccupiedError(attachType, result.Programs, keptReason)
		}
		if err := replaceCgroupOwner(target, program, attachType, displaced.flags); err != nil {
			_ = displaced.Close()
			return legacyCgroupAttachment{}, err
		}
		return legacyCgroupAttachment{mode: cgroupAttachModeNetdReplace, displaced: displaced}, nil
	}
	// Keep the legacy fallback used before multi-only attachment was adopted.
	// Some vendor kernels reject ALLOW_MULTI for otherwise usable hooks. An
	// unflagged attach can replace an existing single-program attachment, so it
	// is attempted only after errors known to indicate unavailable multi attach.
	options.Flags = 0
	if err := rawAttachProgram(options); err != nil {
		return legacyCgroupAttachment{}, err
	}
	return legacyCgroupAttachment{mode: cgroupAttachModeLegacyExclusive}, nil
}

func cgroupMultiAttachUnavailable(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

// rawDetachProgram is a variable so tests can observe the detach that
// precedes restoring a displaced owner without a kernel object.
var rawDetachProgram = func(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	return link.RawDetachProgram(link.RawDetachProgramOptions{Target: target, Program: program, Attach: attachType})
}

func sameProgramIDs(left, right []CiliumEBPF.ProgramID) bool {
	return slices.Equal(left, right)
}

func verifierErrorStage(err error) string {
	var verifierErr *CiliumEBPF.VerifierError
	if errors.As(err, &verifierErr) {
		return fmt.Sprintf("verifier rejected program: %v", verifierErr)
	}
	return ""
}

type programSelection struct {
	section           string
	kernelProgramName string
}

type mapSpecOverride struct {
	name       string
	mapType    CiliumEBPF.MapType
	maxEntries uint32
	flags      uint32
}

func validateKernelObjectName(name string) error {
	if name == "" {
		return E.New("empty eBPF kernel object name")
	}
	if len(name) > kernelObjectNameLimit {
		return E.New("eBPF kernel object name ", name, " exceeds the ", kernelObjectNameLimit, "-byte limit")
	}
	return nil
}

func loadObjectMaps(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	overrides map[string]mapSpecOverride,
) (map[string]*CiliumEBPF.Map, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	clear(spec.Programs)
	for name, mapSpec := range spec.Maps {
		override, selected := overrides[name]
		if !selected {
			delete(spec.Maps, name)
			continue
		}
		if err = validateKernelObjectName(override.name); err != nil {
			return nil, E.Cause(err, "invalid eBPF map override for ", name)
		}
		if override.mapType == CiliumEBPF.UnspecifiedMap || (override.maxEntries == 0 && override.mapType != CiliumEBPF.SkStorage) {
			return nil, E.New("invalid eBPF map override for ", name)
		}
		mapSpec.Name = override.name
		mapSpec.Type = override.mapType
		mapSpec.MaxEntries = override.maxEntries
		mapSpec.Flags = override.flags
		mapSpec.Extra = nil
	}
	for name := range overrides {
		if spec.Maps[name] == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
	}
	collection, err := CiliumEBPF.NewCollection(spec)
	if err != nil {
		return nil, eBPFOperationError("create eBPF maps", err)
	}
	maps := make(map[string]*CiliumEBPF.Map, len(collection.Maps))
	for name, mapInstance := range collection.Maps {
		maps[name] = mapInstance
		delete(collection.Maps, name)
	}
	collection.Close()
	return maps, nil
}

func loadObjectPrograms(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
) ([]*CiliumEBPF.Program, error) {
	return loadObjectProgramsWithOptions(loadSpec, maps, selections, CiliumEBPF.ProgramOptions{})
}

func loadObjectProgramsWithOptions(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
	programOptions CiliumEBPF.ProgramOptions,
) ([]*CiliumEBPF.Program, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	selectedSections := make(map[string]int, len(selections))
	for index, selection := range selections {
		selectedSections[selection.section] = index
	}
	programSymbols := make([]string, len(selections))
	for symbol, program := range spec.Programs {
		index, selected := selectedSections[program.SectionName]
		if !selected {
			delete(spec.Programs, symbol)
			continue
		}
		if program.Type == CiliumEBPF.UnspecifiedProgram {
			return nil, E.New("eBPF program section has unknown type: ", program.SectionName)
		}
		program.Name = selections[index].kernelProgramName
		programSymbols[index] = symbol
	}
	for index, symbol := range programSymbols {
		if symbol == "" {
			return nil, E.New("eBPF object is missing program section ", selections[index].section)
		}
	}
	for name := range spec.Maps {
		if maps[name] == nil {
			delete(spec.Maps, name)
		}
	}
	for name, mapInstance := range maps {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
		info, infoErr := mapInstance.Info()
		if infoErr != nil {
			return nil, E.Cause(infoErr, "inspect replacement eBPF map ", name)
		}
		mapSpec.Type = info.Type
		mapSpec.KeySize = info.KeySize
		mapSpec.ValueSize = info.ValueSize
		mapSpec.MaxEntries = info.MaxEntries
		mapSpec.Flags = info.Flags
		mapSpec.Extra = nil
	}
	collection, err := CiliumEBPF.NewCollectionWithOptions(spec, CiliumEBPF.CollectionOptions{
		MapReplacements: maps,
		Programs:        programOptions,
	})
	if err != nil && !programOptions.LogDisabled && verifierLogRetryMaskedError(err) {
		// cilium/ebpf retries a failed load with a growing verifier log. Before
		// Linux 5.2 the kernel rejects a log buffer over 16 MiB with EINVAL
		// before verifying, and that EINVAL replaces the real error, typically
		// E2BIG from the verifier complexity limit. A load without a log
		// reports the real one.
		retryOptions := programOptions
		retryOptions.LogDisabled = true
		retryCollection, retryErr := CiliumEBPF.NewCollectionWithOptions(spec, CiliumEBPF.CollectionOptions{
			MapReplacements: maps,
			Programs:        retryOptions,
		})
		switch {
		case retryErr == nil:
			collection, err = retryCollection, nil
		case !errors.Is(retryErr, unix.EINVAL):
			err = retryErr
		}
	}
	if err != nil {
		return nil, eBPFOperationError("load eBPF programs", err)
	}
	programs := make([]*CiliumEBPF.Program, len(selections))
	for index, symbol := range programSymbols {
		programs[index] = collection.DetachProgram(symbol)
		if programs[index] == nil {
			_ = closePrograms(programs)
			collection.Close()
			return nil, E.New("loaded eBPF collection is missing program ", symbol)
		}
	}
	collection.Close()
	return programs, nil
}

// verifierLogRetryMaskedError reports an EINVAL that came without any
// verifier output, which is what a rejected verifier log buffer looks like.
func verifierLogRetryMaskedError(err error) bool {
	var verifierErr *CiliumEBPF.VerifierError
	return errors.Is(err, unix.EINVAL) && errors.As(err, &verifierErr) && len(verifierErr.Log) == 0
}

func closePrograms(programs []*CiliumEBPF.Program) error {
	var closeErr error
	for index, program := range slices.Backward(programs) {
		if program == nil {
			continue
		}
		closeErr = E.Errors(closeErr, program.Close())
		programs[index] = nil
	}
	return closeErr
}

func closeMaps(maps map[string]*CiliumEBPF.Map) error {
	var closeErr error
	for name, mapInstance := range maps {
		if mapInstance == nil {
			continue
		}
		closeErr = E.Errors(closeErr, mapInstance.Close())
		delete(maps, name)
	}
	return closeErr
}

func closeObjectResources(programs []*CiliumEBPF.Program, maps map[string]*CiliumEBPF.Map) error {
	return E.Errors(closePrograms(programs), closeMaps(maps))
}
