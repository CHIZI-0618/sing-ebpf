//go:build with_ebpf && (linux || android)

package core

import "testing"

type nilSelfBypassFacade struct{ SelfBypassHandle }
type nilTCBackendFacade struct{ TCBackendHandle }
type nilSharedNetworkBackendFacade struct{ SharedNetworkBackendHandle }

func TestUnwrapTypedNilFacades(t *testing.T) {
	var selfBypass *nilSelfBypassFacade
	if backend := UnwrapSelfBypass(selfBypass); backend != nil {
		t.Fatalf("self-bypass backend = %p, want nil", backend)
	}
	var tcBackend *nilTCBackendFacade
	if backend := UnwrapTCBackend(tcBackend); backend != nil {
		t.Fatalf("TC backend = %p, want nil", backend)
	}
	var sharedBackend *nilSharedNetworkBackendFacade
	if backend := UnwrapSharedNetworkBackend(sharedBackend); backend != nil {
		t.Fatalf("shared-network backend = %p, want nil", backend)
	}
}
