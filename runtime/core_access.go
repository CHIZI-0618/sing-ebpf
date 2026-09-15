//go:build with_ebpf && (linux || android)

package runtime

import (
	public "github.com/CHIZI-0618/sing-ebpf"
	core "github.com/CHIZI-0618/sing-ebpf/internal/core"
)

func rawTCBackend(backend *public.TCBackend) *core.TCBackend {
	return core.UnwrapTCBackend(backend)
}

func rawSharedPacketRewriteBackend(backend *public.SharedPacketRewriteBackend) *core.SharedPacketRewriteBackend {
	return core.UnwrapSharedPacketRewriteBackend(backend)
}
