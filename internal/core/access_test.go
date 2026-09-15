//go:build with_ebpf && (linux || android)

package core

import "testing"

type nilSelfBypassFacade struct{ SelfBypassHandle }
type nilTCBackendFacade struct{ TCBackendHandle }
type nilSharedPacketRewriteBackendFacade struct {
	SharedPacketRewriteBackendHandle
}

func TestUnwrapTypedNilFacades(t *testing.T) {
	var selfBypass *nilSelfBypassFacade
	if backend := UnwrapSelfBypass(selfBypass); backend != nil {
		t.Fatalf("self-bypass backend = %p, want nil", backend)
	}
	var tcBackend *nilTCBackendFacade
	if backend := UnwrapTCBackend(tcBackend); backend != nil {
		t.Fatalf("TC backend = %p, want nil", backend)
	}
	var sharedBackend *nilSharedPacketRewriteBackendFacade
	if backend := UnwrapSharedPacketRewriteBackend(sharedBackend); backend != nil {
		t.Fatalf("shared-network backend = %p, want nil", backend)
	}
}
