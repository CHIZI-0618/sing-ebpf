//go:build with_ebpf && (linux || android)

package core

import (
	"errors"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// probeGetpeernameSupport reports whether the kernel accepts cgroup
// getpeername programs (Linux 5.8+). The hooks only restore the original
// destination a redirected socket reports as its peer, so a kernel or policy
// that rejects them leaves interception itself unaffected.
func probeGetpeernameSupport(attachType CiliumEBPF.AttachType) bool {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Type:       CiliumEBPF.CGroupSockAddr,
		AttachType: attachType,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	_ = program.Close()
	return true
}

func cgroupGetpeernameSlot(slot int) bool {
	return slot == cgroupProgramGetpeername4 || slot == cgroupProgramGetpeername6
}

func getpeernameUnavailable(err error) bool {
	return socketReleaseAttachUnavailable(err) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, CiliumEBPF.ErrNotSupported)
}
