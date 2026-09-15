//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestLegacyCgroupProgramLinkRetainsTargetAfterDetachFailure(t *testing.T) {
	cgroupFile, err := os.Create(filepath.Join(t.TempDir(), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	programLink := &legacyCgroupProgramLink{
		cgroupFile: cgroupFile,
		detachProgram: func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error {
			attempts++
			if attempts == 1 {
				return unix.EBUSY
			}
			return nil
		},
	}
	if err = programLink.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if programLink.IsClosed() {
		t.Fatal("legacy cgroup target was discarded after a failed detach")
	}
	if _, err = cgroupFile.Stat(); err != nil {
		t.Fatalf("legacy cgroup target was closed after a failed detach: %v", err)
	}
	if err = programLink.Close(); err != nil {
		t.Fatalf("retry legacy cgroup detach: %v", err)
	}
	if !programLink.IsClosed() {
		t.Fatal("legacy cgroup target remained open after a successful detach")
	}
}

type retryableTestCgroupProgramLink struct {
	failures int
	closed   bool
}

func (l *retryableTestCgroupProgramLink) Close() error {
	if l.closed {
		return nil
	}
	if l.failures > 0 {
		l.failures--
		return unix.EBUSY
	}
	l.closed = true
	return nil
}

func (l *retryableTestCgroupProgramLink) IsClosed() bool { return l.closed }
