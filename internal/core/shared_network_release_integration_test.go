//go:build with_ebpf && linux && ebpf_integration

package core

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestSharedNetworkTCPReleaseKeepsFlowReusedBySYN covers a client reopening a
// connection from the tuple of one that just closed. The ingress program then
// reuses the cached flow and stamps its last_seen_ns; the delayed release of
// the closed connection must not delete the flow the new one now uses, while a
// flow nobody reused is still deleted when its grace expires.
func TestSharedNetworkTCPReleaseKeepsFlowReusedBySYN(t *testing.T) {
	policy := newTestSharedNetworkForceInterceptPolicy(t, "198.18.0.0/15")
	backend, err := PrepareSharedPacketRewrite(newTestSharedPacketRewriteConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	install := func(clientPort uint16, generation uint64) SharedPacketRewriteFlowHandle {
		originalKey := sharedNetworkOriginalKey{
			InterfaceIndex: 7, Family: unix.AF_INET, Protocol: ProtocolTCP,
			ClientPort: clientPort, OriginalPort: 443,
		}
		copy(originalKey.ClientAddr[:], []byte{192, 0, 2, 10})
		copy(originalKey.OriginalAddr[:], []byte{203, 0, 113, 10})
		listenerKey := sharedNetworkListenerKey{
			Family: unix.AF_INET, Protocol: ProtocolTCP, ListenerPort: 9309, ClientPort: clientPort,
		}
		copy(listenerKey.TokenAddr[:], []byte{127, 1, 0, byte(clientPort)})
		copy(listenerKey.ClientAddr[:], originalKey.ClientAddr[:])
		// Reserved before the release; a booted VM may not have run 10 s yet.
		token := sharedNetworkTokenValue{Generation: generation, LastSeenNS: 1}
		copy(token.TokenAddr[:], listenerKey.TokenAddr[:])
		original := sharedNetworkOriginalValue{
			Family: unix.AF_INET, Protocol: ProtocolTCP, Port: 443, InterfaceIndex: 7, Generation: generation,
		}
		copy(original.Addr[:], originalKey.OriginalAddr[:])
		if err := updateMap(int(backend.runtime.flow_by_original_map_fd), unsafe.Pointer(&originalKey), unsafe.Pointer(&token)); err != nil {
			t.Fatal(err)
		}
		if err := updateMap(int(backend.runtime.flow_by_token_map_fd), unsafe.Pointer(&listenerKey), unsafe.Pointer(&original)); err != nil {
			t.Fatal(err)
		}
		return SharedPacketRewriteFlowHandle{originalKey: originalKey, listenerKey: listenerKey, generation: generation}
	}
	closed := install(40001, 11)
	reused := install(40002, 12)
	backend.flowAccess.Lock()
	for _, flow := range []SharedPacketRewriteFlowHandle{closed, reused} {
		backend.retainFlowLocked(flow)
	}
	backend.flowAccess.Unlock()
	for _, flow := range []SharedPacketRewriteFlowHandle{closed, reused} {
		if err = backend.ReleaseFlow(&flow); err != nil {
			t.Fatal(err)
		}
	}
	// What the ingress program does when an initial SYN reuses the flow.
	var token sharedNetworkTokenValue
	if err = lookupMap(int(backend.runtime.flow_by_original_map_fd), unsafe.Pointer(&reused.originalKey), unsafe.Pointer(&token)); err != nil {
		t.Fatal(err)
	}
	token.LastSeenNS = monotonicNowNS()
	if err = updateMap(int(backend.runtime.flow_by_original_map_fd), unsafe.Pointer(&reused.originalKey), unsafe.Pointer(&token)); err != nil {
		t.Fatal(err)
	}

	if _, err = backend.FlushReleasedTCPFlows(time.Now().Add(2*sharedNetworkTCPReleaseGrace), 16); err != nil {
		t.Fatal(err)
	}
	present := func(flow SharedPacketRewriteFlowHandle) bool {
		var token sharedNetworkTokenValue
		err := lookupMap(int(backend.runtime.flow_by_original_map_fd), unsafe.Pointer(&flow.originalKey), unsafe.Pointer(&token))
		if err != nil && !errors.Is(err, unix.ENOENT) {
			t.Fatal(err)
		}
		var original sharedNetworkOriginalValue
		tokenErr := lookupMap(int(backend.runtime.flow_by_token_map_fd), unsafe.Pointer(&flow.listenerKey), unsafe.Pointer(&original))
		if (err == nil) != (tokenErr == nil) {
			t.Fatalf("flow %d is half deleted: original=%v token=%v", flow.generation, err, tokenErr)
		}
		return err == nil
	}
	if present(closed) {
		t.Fatal("an expired release that nobody reused kept its flow")
	}
	if !present(reused) {
		t.Fatal("the release of a closed connection deleted the flow a new SYN reused")
	}
	backend.flowAccess.Lock()
	pending := len(backend.flowReleases)
	backend.flowAccess.Unlock()
	if pending != 0 {
		t.Fatalf("%d releases still pending after the flush", pending)
	}
}
