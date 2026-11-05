//go:build with_ebpf && (linux || android)

package core

// tcFlowStore is the single ownership boundary for tuple-keyed TC flow state.
// The individual stores retain their protocol-specific ABI and cleanup rules,
// while the backend only needs one lifecycle operation for rebuild and close.
type tcFlowStore struct {
	assignment tcAssignmentStore
	returns    tcReturnStore
}

func (s *tcFlowStore) reset() {
	*s = tcFlowStore{}
}
