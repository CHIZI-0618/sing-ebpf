//go:build with_ebpf && (linux || android)

package core

import "sync"

// cgroupRecoveryStore owns userspace state for bounded UDP recovery cleanup.
// The kernel map remains part of the cgroup runtime; this store owns only the
// cursor, candidate buffer and serialization needed by maintenance callers.
type cgroupRecoveryStore struct {
	access     sync.Mutex
	scratch    mapScanScratch[listenerLookupKey, originalDestinationValue]
	candidates []udpRecoveryEntry
	removed    uint32
}

func (s *cgroupRecoveryStore) reset() {
	// Keep access intact: callers reset the store while holding this mutex
	// during backend shutdown. Zeroing the whole struct would replace the
	// locked mutex and make the deferred Unlock panic.
	s.scratch = mapScanScratch[listenerLookupKey, originalDestinationValue]{}
	s.candidates = nil
	s.removed = 0
}
