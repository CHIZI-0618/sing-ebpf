//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestTCFlowStoreResetPreservesLocks(t *testing.T) {
	var store tcFlowStore
	store.assignment.sweepAccess.Lock()
	store.returns.access.Lock()
	store.reset()
	store.returns.access.Unlock()
	store.assignment.sweepAccess.Unlock()
	if store.assignment.sweepRemoved != 0 || store.returns.sweepRemoved != 0 || store.returns.references != nil {
		t.Fatalf("reset left flow state: assignment_removed=%d return_removed=%d references=%v", store.assignment.sweepRemoved, store.returns.sweepRemoved, store.returns.references != nil)
	}
}
