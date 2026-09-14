//go:build with_ebpf && (linux || android)

package core

// The handle types deliberately expose no exported accessors. Public facade
// types embed them, which promotes these package-private methods into their
// method sets. Code inside this internal package can therefore unwrap a facade
// without placing raw maps, programs, or file descriptors on the public API.

type SelfBypassHandle struct {
	backend *SelfBypass
}

func NewSelfBypassHandle(backend *SelfBypass) SelfBypassHandle {
	return SelfBypassHandle{backend: backend}
}

func (h SelfBypassHandle) selfBypassBackend() *SelfBypass {
	return h.backend
}

func UnwrapSelfBypass(value any) *SelfBypass {
	if value == nil {
		return nil
	}
	carrier, loaded := value.(interface{ selfBypassBackend() *SelfBypass })
	if !loaded {
		panic("invalid sing-ebpf self-bypass facade")
	}
	return carrier.selfBypassBackend()
}

func PrepareCgroupWithSelfBypass(config CgroupConfig, value any) (*CgroupBackend, error) {
	if bypass := UnwrapSelfBypass(value); bypass != nil {
		config.SelfBypassMap = bypass.Map()
	}
	return PrepareCgroup(config)
}

func AttachProcessTrackerWithSelfBypass(config ProcessTrackerConfig, value any) (*ProcessTracker, error) {
	if bypass := UnwrapSelfBypass(value); bypass != nil {
		config.MetadataMap = bypass.Map()
	}
	return AttachProcessTracker(config)
}

func PrepareTCWithSelfBypass(config TCConfig, value any) (*TCBackend, error) {
	if bypass := UnwrapSelfBypass(value); bypass != nil {
		config.SelfBypassMap = bypass.Map()
	}
	return PrepareTC(config)
}

type TCBackendHandle struct {
	backend *TCBackend
}

func NewTCBackendHandle(backend *TCBackend) TCBackendHandle {
	return TCBackendHandle{backend: backend}
}

func (h TCBackendHandle) tcBackend() *TCBackend {
	return h.backend
}

func UnwrapTCBackend(value any) *TCBackend {
	if value == nil {
		return nil
	}
	carrier, loaded := value.(interface{ tcBackend() *TCBackend })
	if !loaded {
		panic("invalid sing-ebpf TC backend facade")
	}
	return carrier.tcBackend()
}

type SharedNetworkBackendHandle struct {
	backend *SharedNetworkBackend
}

func NewSharedNetworkBackendHandle(backend *SharedNetworkBackend) SharedNetworkBackendHandle {
	return SharedNetworkBackendHandle{backend: backend}
}

func (h SharedNetworkBackendHandle) sharedNetworkBackend() *SharedNetworkBackend {
	return h.backend
}

func UnwrapSharedNetworkBackend(value any) *SharedNetworkBackend {
	if value == nil {
		return nil
	}
	carrier, loaded := value.(interface{ sharedNetworkBackend() *SharedNetworkBackend })
	if !loaded {
		panic("invalid sing-ebpf shared-network backend facade")
	}
	return carrier.sharedNetworkBackend()
}
