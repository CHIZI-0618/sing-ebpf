//go:build with_ebpf && (linux || android)

package core

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// ResetNetworkState advances the generation used by cgroup UDP decision
// caches. Redirect tokens, connected peers, and socket-release watches belong
// to live sockets rather than to an uplink, so they deliberately survive a
// network handover. In particular, userspace cannot enumerate and delete
// BPF_MAP_TYPE_SK_STORAGE values: clearing their redirect maps would leave a
// live socket rewriting packets with a token whose original destination had
// already been discarded.
//
// Both the hash-map and socket-storage caches carry this generation. Their
// next lookup treats an old value as a miss and rebuilds it against the current
// host and bypass policies. Stale hash entries remain harmless LRU occupants
// until replaced or evicted, avoiding a delete-versus-insert race with packets
// processed concurrently with this update.
func (b *CgroupBackend) ResetNetworkState() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	previousGeneration := b.networkGeneration
	b.networkGeneration++
	if err := b.updateCgroupControl(b.listenerPort); err != nil {
		b.networkGeneration = previousGeneration
		return E.Cause(err, "advance cgroup eBPF network generation")
	}
	return nil
}
