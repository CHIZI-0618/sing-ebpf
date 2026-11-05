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
	s.assignment.reset()
	s.returns.reset()
}

func (s *tcAssignmentStore) reset() {
	s.mapFD = 0
	s.capacity = 0
	s.sweepRemoved = 0
	s.sweepScratch = mapScanScratch[tcAssignKey, TCAssignment]{}
	s.candidates = nil
}

func (s *tcReturnStore) reset() {
	s.references = nil
	s.sweepRemoved = 0
	s.sweepScratch = mapScanScratch[tcAssignKey, tcReturnValue]{}
	s.fragmentScratch = mapScanScratch[tcAssignKey, tcReturnValue]{}
}
