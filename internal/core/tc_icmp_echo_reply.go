//go:build with_ebpf && (linux || android)

package core

import (
	CiliumEBPF "github.com/cilium/ebpf"
)

// This file is TCBackend's thin delegation to ICMPEchoReplyBackend (see
// icmp_echo_reply_backend.go for the object itself and why it is a standalone
// backend rather than fields inline on TCBackend). TCBackend's own public
// API here remains stable for consumers: ICMPEchoReplyEnabled, the program accessors, and
// prepareTC's population of b.icmpEchoReply (in tc.go) are the only places
// that know ICMPEchoReplyBackend exists underneath.

// ICMPEchoReplyEnabled reports whether this backend loaded the icmp_echo_reply
// object. A consumer's TC data plane uses this to decide whether to
// attach the extra local/shared reply filters at all.
func (b *TCBackend) ICMPEchoReplyEnabled() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.icmpEchoReply != nil
}

func (b *TCBackend) ICMPEchoLocalReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.icmpEchoReply
	b.access.RUnlock()
	return backend.LocalReplyProgramFD(framing)
}

func (b *TCBackend) ICMPEchoLocalReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.icmpEchoReply
	b.access.RUnlock()
	return backend.LocalReplyProgram(framing)
}

func (b *TCBackend) ICMPEchoSharedReplyProgramFD(framing TCLinkFraming) int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	backend := b.icmpEchoReply
	b.access.RUnlock()
	return backend.SharedReplyProgramFD(framing)
}

func (b *TCBackend) ICMPEchoSharedReplyProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	if b == nil {
		return nil
	}
	b.access.RLock()
	backend := b.icmpEchoReply
	b.access.RUnlock()
	return backend.SharedReplyProgram(framing)
}

func (b *TCBackend) icmpEchoReplyBackend() *ICMPEchoReplyBackend {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.icmpEchoReply
}

// ICMPEchoReplyCount, ICMPEchoPassThroughCount, and
// ICMPEchoRewriteFailureCount delegate to the underlying ICMPEchoReplyBackend's
// own counters (see that type's doc comments); each reports errBackendClosed
// if icmp_echo_reply was never enabled on this backend.
func (b *TCBackend) ICMPEchoReplyCount() (uint64, error) {
	return b.icmpEchoReplyBackend().ReplyCount()
}

func (b *TCBackend) ICMPEchoPassThroughCount() (uint64, error) {
	return b.icmpEchoReplyBackend().PassThroughCount()
}

func (b *TCBackend) ICMPEchoRewriteFailureCount() (uint64, error) {
	return b.icmpEchoReplyBackend().RewriteFailureCount()
}
