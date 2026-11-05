//go:build with_ebpf && (linux || android)

package core

// networkGenerationMask reserves the high bit used by the compact TC return
// route state. Keeping the wrap and normalization rules in one place prevents
// cgroup and TC from disagreeing after a long-running process crosses the
// uint32 boundary.
const networkGenerationMask uint32 = 0x7fffffff

func normalizeNetworkGeneration(generation uint32) uint32 {
	generation &= networkGenerationMask
	if generation == 0 {
		return 1
	}
	return generation
}

func nextNetworkGeneration(current uint32) uint32 {
	return normalizeNetworkGeneration(current + 1)
}
