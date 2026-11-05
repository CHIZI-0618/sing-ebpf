//go:build with_ebpf && (linux || android)

package core

import "testing"

func TestCgroupRecoveryStoreResetPreservesLockedAccess(t *testing.T) {
	var store cgroupRecoveryStore
	store.access.Lock()
	store.scratch = mapScanScratch[listenerLookupKey, originalDestinationValue]{cursorValid: true}
	store.candidates = make([]udpRecoveryEntry, 1)
	store.removed = 3
	store.reset()
	store.access.Unlock()
	if store.scratch.cursorValid || store.candidates != nil || store.removed != 0 {
		t.Fatalf("reset left recovery state: cursor_valid=%v candidates=%d removed=%d", store.scratch.cursorValid, len(store.candidates), store.removed)
	}
}
