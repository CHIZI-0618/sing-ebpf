//go:build with_ebpf && (linux || android)

package runtime

import (
	"testing"

	core "github.com/CHIZI-0618/sing-ebpf"
)

func newLoopbackTestTCBackend(t *testing.T) *core.TCBackend {
	t.Helper()
	policy, err := core.CompileActionPolicy(core.ActionPolicy{
		EnableTCP: true,
		Local:     core.ActionScope{Default: core.DecisionIntercept},
		Shared:    core.ActionScope{Default: core.DecisionIntercept},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := core.PrepareTC(core.TCConfig{
		ListenerPort: 23457,
		EnableLocal:  true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Skipf("cannot prepare a real TC eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}
