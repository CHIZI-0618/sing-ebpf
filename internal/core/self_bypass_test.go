//go:build with_ebpf && (linux || android)

package core

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func TestSelfBypassStorageMapABI(t *testing.T) {
	spec := selfBypassStorageMapSpec()
	if spec.Name != "sb_self_storage" || spec.Type != CiliumEBPF.SkStorage || spec.KeySize != 4 || spec.ValueSize != 4 || spec.MaxEntries != 0 || spec.Flags&bpfFlagNoPrealloc == 0 {
		t.Fatalf("unexpected self-bypass storage map spec: %+v", spec)
	}
	if got := spec.Key.TypeName(); got != "int" {
		t.Fatalf("self-bypass storage key BTF type = %q, want int", got)
	}
	if got := spec.Value.TypeName(); got != "__u32" {
		t.Fatalf("self-bypass storage value BTF type = %q, want __u32", got)
	}
	if unsafe.Sizeof(uint32(0)) != 4 {
		t.Fatal("unexpected uint32 ABI")
	}
}

func TestProcessCgroupExclusive(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cgroup.procs")
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(path, []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err := processCgroupExclusive(directory)
	if err != nil || !exclusive {
		t.Fatalf("single-process cgroup was not exclusive: exclusive=%v err=%v", exclusive, err)
	}
	if err = os.WriteFile(path, []byte(pid+"\n"+strconv.Itoa(os.Getpid()+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err = processCgroupExclusive(directory)
	if err != nil || exclusive {
		t.Fatalf("shared cgroup was treated as exclusive: exclusive=%v err=%v", exclusive, err)
	}
}

func TestSelfBypassCloseRetainsFailedLegacyAttachment(t *testing.T) {
	programLink := &retryableTestCgroupProgramLink{failures: 1}
	bypass := &SelfBypass{links: []cgroupProgramLink{programLink}}
	if err := bypass.Close(); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if bypass.IsClosed() {
		t.Fatal("self-bypass discarded a failed legacy attachment")
	}
	if err := bypass.Close(); err != nil {
		t.Fatalf("retry self-bypass close: %v", err)
	}
	if !bypass.IsClosed() {
		t.Fatal("self-bypass remained open after cleanup retry")
	}
}

func TestProcessCgroupExclusiveRejectsPopulatedDescendant(t *testing.T) {
	directory := t.TempDir()
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(filepath.Join(directory, "cgroup.procs"), []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(directory, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid()+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err := processCgroupExclusive(directory)
	if err != nil || exclusive {
		t.Fatalf("populated descendant was treated as exclusive: exclusive=%v err=%v", exclusive, err)
	}
}

func TestSelfBypassInstructionsUseSocketCookie(t *testing.T) {
	for name, instructions := range map[string]asm.Instructions{
		"create":      selfBypassCreateInstructions(1, 1),
		"release":     selfBypassReleaseInstructions(1),
		"socket_addr": selfBypassSocketAddrInstructions(1, 1),
	} {
		found := false
		for _, instruction := range instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetSocketCookie {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s self-bypass instructions do not read the socket cookie", name)
		}
	}
}

func TestSelfBypassStorageInstructionsUseStorageHelpers(t *testing.T) {
	for name, instructions := range map[string]asm.Instructions{
		"create":      selfBypassCreateInstructions(1, 1, 2),
		"release":     selfBypassReleaseInstructions(1, 2),
		"socket_addr": selfBypassSocketAddrInstructions(1, 1, 2),
	} {
		var get, delete int
		for _, instruction := range instructions {
			if !instruction.IsBuiltinCall() {
				continue
			}
			switch asm.BuiltinFunc(instruction.Constant) {
			case asm.FnSkStorageGet:
				get++
			case asm.FnSkStorageDelete:
				delete++
			}
		}
		if name == "release" && delete != 1 {
			t.Fatalf("%s storage delete calls = %d, want 1", name, delete)
		}
		if name != "release" && get != 1 {
			t.Fatalf("%s storage get calls = %d, want 1", name, get)
		}
	}
}

func TestSelfBypassSocketAddrStorageUsesSocketPointer(t *testing.T) {
	instructions := selfBypassStorageMarkInstructions(1, true)
	found := false
	for _, instruction := range instructions {
		if instruction.OpCode == asm.LoadMemOp(asm.DWord) &&
			instruction.Dst == asm.R2 && instruction.Src == asm.R6 &&
			instruction.Offset == bpfSockAddrSocketOffset {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("socket-address storage lookup does not load ctx->sk at offset %d: %v", bpfSockAddrSocketOffset, instructions)
	}
	if instructions[0].OpCode != asm.LoadMapPtr(asm.R1, 1).OpCode {
		t.Fatalf("socket-address storage lookup does not load the storage map: %v", instructions)
	}
}

func TestSelfBypassInstructionsRecordOwner(t *testing.T) {
	const owner = 4242
	for name, instructions := range map[string]asm.Instructions{
		"create":      selfBypassCreateInstructions(1, owner),
		"socket_addr": selfBypassSocketAddrInstructions(1, owner),
	} {
		pidIndex, cookieIndex, ownerJump := -1, -1, false
		for index, instruction := range instructions {
			if instruction.IsBuiltinCall() {
				switch asm.BuiltinFunc(instruction.Constant) {
				case asm.FnGetCurrentPidTgid:
					if pidIndex < 0 {
						pidIndex = index
					}
				case asm.FnGetSocketCookie:
					if cookieIndex < 0 {
						cookieIndex = index
					}
				}
			}
			if instruction.OpCode.JumpOp() == asm.JNE && instruction.Constant == owner && instruction.Reference() == "allow" {
				ownerJump = true
			}
		}
		if pidIndex < 0 || cookieIndex < 0 || pidIndex > cookieIndex || !ownerJump {
			t.Fatalf("%s self-bypass instructions do not skip sockets of other processes: pid=%d cookie=%d jump=%v", name, pidIndex, cookieIndex, ownerJump)
		}
		if first := instructions[0]; first.OpCode.ALUOp() != asm.Mov || first.Dst != asm.R6 || first.Src != asm.R1 {
			t.Fatalf("%s self-bypass instructions do not preserve the context: %v", name, first)
		}
		if restore := instructions[cookieIndex-1]; restore.OpCode.ALUOp() != asm.Mov || restore.Dst != asm.R1 || restore.Src != asm.R6 {
			t.Fatalf("%s self-bypass instructions do not restore the context before the cookie helper: %v", name, restore)
		}
		if err := instructions.Marshal(io.Discard, binary.LittleEndian); err != nil {
			t.Fatalf("%s self-bypass instructions do not assemble: %v", name, err)
		}
	}
	for _, instruction := range selfBypassReleaseInstructions(1) {
		if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetCurrentPidTgid {
			t.Fatal("release instructions must delete any registered cookie regardless of the releasing task")
		}
	}
}

func TestSelfBypassOwnerTGID(t *testing.T) {
	owner, err := selfBypassOwnerTGID()
	if err != nil || owner != uint32(os.Getpid()) {
		t.Fatalf("owner = %d, %v; want %d", owner, err, os.Getpid())
	}
}

func TestSelfBypassSocketAddrHooks(t *testing.T) {
	hooks := selfBypassSocketAddrHooks(SelfBypassCgroupConfig{
		EnableTCP:  true,
		EnableUDP:  true,
		EnableIPv6: true,
	})
	if len(hooks) != 4 {
		t.Fatalf("unexpected dual-stack self-bypass hook count: %d", len(hooks))
	}
	if hooks[0].kernelProgramName != kernelProgramNameSelfConnect4 ||
		hooks[1].kernelProgramName != kernelProgramNameSelfConnect6 ||
		hooks[2].kernelProgramName != kernelProgramNameSelfSendmsg4 ||
		hooks[3].kernelProgramName != kernelProgramNameSelfSendmsg6 {
		t.Fatalf("unexpected self-bypass kernel program names: %+v", hooks)
	}
	if hooks[0].attachType != CiliumEBPF.AttachCGroupInet4Connect ||
		hooks[1].attachType != CiliumEBPF.AttachCGroupInet6Connect ||
		hooks[2].attachType != CiliumEBPF.AttachCGroupUDP4Sendmsg ||
		hooks[3].attachType != CiliumEBPF.AttachCGroupUDP6Sendmsg {
		t.Fatalf("unexpected self-bypass hooks: %+v", hooks)
	}
	ipv4Only := selfBypassSocketAddrHooks(SelfBypassCgroupConfig{EnableTCP: true})
	if len(ipv4Only) != 1 || ipv4Only[0].attachType != CiliumEBPF.AttachCGroupInet4Connect {
		t.Fatalf("unexpected IPv4-only self-bypass hooks: %+v", ipv4Only)
	}
}

func TestSelfBypassModes(t *testing.T) {
	tests := []struct {
		mode         SelfBypassMode
		name         string
		cleanup      string
		cgroupAttach bool
	}{
		{SelfBypassUserspace, "userspace_socket_cookie", "userspace_unregister", false},
		{SelfBypassCgroupSocket, "cgroup_socket_cookie", "socket_release", true},
		{SelfBypassCgroupSocketAddr, "cgroup_socket_addr", "userspace_unregister", true},
		{SelfBypassCgroupSocketAddrRelease, "cgroup_socket_addr_release", "socket_release", true},
		{SelfBypassUserspaceRelease, "userspace_socket_cookie_release", "userspace_unregister", false},
	}
	for _, test := range tests {
		if test.mode.String() != test.name {
			t.Fatalf("mode %d string = %q, want %q", test.mode, test.mode.String(), test.name)
		}
		if test.mode.CleanupMode() != test.cleanup {
			t.Fatalf("mode %s cleanup = %q, want %q", test.name, test.mode.CleanupMode(), test.cleanup)
		}
		bypass := &SelfBypass{}
		bypass.mode.Store(uint32(test.mode))
		if bypass.CgroupAttached() != test.cgroupAttach {
			t.Fatalf("mode %s cgroup attached = %v, want %v", test.name, bypass.CgroupAttached(), test.cgroupAttach)
		}
	}
}

// Consumers construct SelfBypass while building a configuration, which also
// happens in unprivileged configuration checks. Construction must therefore
// not create kernel objects.
func TestNewSelfBypassCreatesNoKernelObject(t *testing.T) {
	bypass, err := NewSelfBypassWithCapacity(CompactSelfBypassSocketCapacity)
	if err != nil {
		t.Fatal(err)
	}
	if bypass.Map() != nil {
		t.Fatal("constructor created the socket-cookie map")
	}
	if bypass.IsClosed() {
		t.Fatal("an unprepared self-bypass reported itself closed")
	}
	if err = bypass.Close(); err != nil {
		t.Fatal(err)
	}
	if !bypass.IsClosed() {
		t.Fatal("self-bypass remained open after Close")
	}
	if _, err = bypass.PreparedMap(); !errors.Is(err, errSelfBypassClosed) {
		t.Fatalf("prepare after close = %v, want errSelfBypassClosed", err)
	}
	if err = bypass.RegisterSocket(nil); err != nil {
		t.Fatalf("register after close = %v, want nil", err)
	}
}

func TestNewSelfBypassRejectsInvalidCapacity(t *testing.T) {
	for _, capacity := range []uint32{0, MaxConfigurableMapCapacity + 1} {
		if _, err := NewSelfBypassWithCapacity(capacity); err == nil {
			t.Fatalf("capacity %d was accepted", capacity)
		}
	}
}

func preparedTestSelfBypass(t *testing.T) *SelfBypass {
	t.Helper()
	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bypass.Close() })
	return bypass
}

func testSocketCookie(t *testing.T) (net.PacketConn, syscall.RawConn, uint64) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var cookie uint64
	if err = control.Raw(rawConn, func(fd uintptr) error {
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn, rawConn, cookie
}

func TestOpenSocketCookiesTracksDescriptors(t *testing.T) {
	conn, _, cookie := testSocketCookie(t)
	open, err := openSocketCookies()
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if _, loaded := open[cookie]; !loaded {
		_ = conn.Close()
		t.Fatal("open socket missing from descriptor scan")
	}
	_ = conn.Close()
	open, err = openSocketCookies()
	if err != nil {
		t.Fatal(err)
	}
	if _, loaded := open[cookie]; loaded {
		t.Fatal("closed socket still reported open")
	}
}

func TestSelfBypassReclaimsClosedSocketsWhenFull(t *testing.T) {
	bypass, err := NewSelfBypassWithCapacity(3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bypass.Close() })
	sockets, err := bypass.PreparedMap()
	if err != nil {
		t.Skipf("BPF maps are unavailable here: %v", err)
	}
	live, liveRaw, liveCookie := testSocketCookie(t)
	defer live.Close()
	closed, closedRaw, closedCookie := testSocketCookie(t)
	for _, rawConn := range []syscall.RawConn{liveRaw, closedRaw} {
		if _, err = bypass.RegisterSocketCookie(rawConn); err != nil {
			t.Fatal(err)
		}
	}
	_ = closed.Close()
	policyCookie := uint64(math.MaxUint64)
	policyValue := uint32(SocketMetadataPolicyBypass)
	if err = sockets.Update(&policyCookie, &policyValue, CiliumEBPF.UpdateAny); err != nil {
		t.Fatal(err)
	}
	next, nextRaw, nextCookie := testSocketCookie(t)
	defer next.Close()
	if _, err = bypass.RegisterSocketCookie(nextRaw); err != nil {
		t.Fatalf("register into a map full of closed sockets: %v", err)
	}
	var value uint32
	for _, cookie := range []uint64{liveCookie, nextCookie, policyCookie} {
		if err = sockets.Lookup(&cookie, &value); err != nil {
			t.Fatalf("entry %d was removed: %v", cookie, err)
		}
	}
	if err = sockets.Lookup(&closedCookie, &value); !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
		t.Fatalf("closed socket entry was kept: %v", err)
	}
}

func TestSelfBypassPreparedMapIsStable(t *testing.T) {
	bypass := preparedTestSelfBypass(t)
	first, err := bypass.PreparedMap()
	if err != nil {
		t.Skipf("BPF maps are unavailable here: %v", err)
	}
	second, err := bypass.PreparedMap()
	if err != nil {
		t.Fatal(err)
	}
	if first != second || bypass.Map() != first {
		t.Fatal("the socket-cookie map was created more than once")
	}
}

// A socket created before any data plane prepared the map must still be
// registered, in the same map the data plane later shares.
func TestSelfBypassRegisterSocketCreatesMap(t *testing.T) {
	bypass := preparedTestSelfBypass(t)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = bypass.RegisterSocket(rawConn); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("BPF maps are unavailable here: %v", err)
		}
		t.Fatal(err)
	}
	sockets := bypass.Map()
	if sockets == nil {
		t.Fatal("registration did not create the socket-cookie map")
	}
	shared, err := bypass.PreparedMap()
	if err != nil || shared != sockets {
		t.Fatalf("data plane would receive a different map: %v", err)
	}
	var cookie uint64
	if err = control.Raw(rawConn, func(fd uintptr) error {
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var value uint32
	if err = sockets.Lookup(&cookie, &value); err != nil || value != 1 {
		t.Fatalf("registered socket missing from the map: value=%d err=%v", value, err)
	}
	// UserspaceRelease uses the kernel hook only as a fallback. The userspace
	// owner must still be able to remove its entry, and a second removal is
	// harmless when the kernel hook races with it.
	bypass.mode.Store(uint32(SelfBypassUserspaceRelease))
	if err = bypass.UnregisterSocket(rawConn); err != nil {
		t.Fatalf("userspace-release unregister failed: %v", err)
	}
	if err = bypass.UnregisterSocket(rawConn); err != nil {
		t.Fatalf("userspace-release duplicate unregister failed: %v", err)
	}
}
