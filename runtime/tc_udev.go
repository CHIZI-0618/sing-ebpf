//go:build with_ebpf && (linux || android)

package runtime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// tcUdevSettleTimeout bounds how long creating the delivery link waits for udev
// to finish with the host end of the new pair. udev normally needs tens of milliseconds; past
// this the runtime proceeds, and the infrastructure repair reasserts whatever
// udev changes afterwards.
var tcUdevSettleTimeout = 3 * time.Second

const (
	tcUdevControlSocket = "/run/udev/control"
	// tcUdevMonitorGroup is UDEV_MONITOR_UDEV: udevd rebroadcasts each event
	// there once its rules and RUN programs have completed.
	tcUdevMonitorGroup             = 2
	tcUdevMonitorBufferSize        = 1 << 20
	tcUdevMonitorHeaderSize        = 40
	tcUdevMonitorMagic      uint32 = 0xfeedcafe
)

var tcUdevMonitorPrefix = []byte("libudev\x00")

// tcUdevSettle waits for udevd to finish processing the "add" events of newly
// created network interfaces.
//
// udev configures every network interface it sees appear: .link files apply
// address, MTU and offload policy (systemd's 99-default.link replaces a
// kernel-generated MAC address), and 99-systemd.rules runs systemd-sysctl for
// the interface. Both land tens of milliseconds after the link is created,
// silently replacing what the runtime configured before that, and no rtnetlink
// link event reports a sysctl change. Waiting for udevd's processed event
// orders the runtime's own configuration after udev's.
//
// Only the host end of an isolated delivery pair is in udevd's namespace; the
// private end is created directly in the caller-owned namespace, whose device
// events udevd never receives.
type tcUdevSettle struct {
	fd      int
	pending map[string]struct{}
}

// beginTCUdevSettle subscribes to udevd's processed events for interfaceNames.
// It must be called before the interfaces are created, so their events cannot
// be missed. It returns nil when udevd does not manage the calling thread's
// network namespace: no udevd runs (Android, most containers), or the thread is
// in a namespace other than the one udevd receives device events from.
func beginTCUdevSettle(interfaceNames ...string) *tcUdevSettle {
	if !tcUdevManagesNetworkNamespace() {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return nil
	}
	// Other devices' events share the group; a larger buffer keeps a burst of
	// them from overflowing the socket before the pair's own events arrive.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, tcUdevMonitorBufferSize) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, tcUdevMonitorBufferSize)
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: tcUdevMonitorGroup}); err != nil {
		_ = unix.Close(fd)
		return nil
	}
	pending := make(map[string]struct{}, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		pending[interfaceName] = struct{}{}
	}
	return &tcUdevSettle{fd: fd, pending: pending}
}

// tcUdevManagesNetworkNamespace reports whether udevd receives the device
// events of the calling thread's network namespace. The kernel delivers a
// network device's uevents only to its own namespace, and udevd listens in the
// namespace of PID 1. The thread's namespace is compared rather than the
// process's: callers may run on a thread locked into another namespace.
func tcUdevManagesNetworkNamespace() bool {
	if _, err := os.Stat(tcUdevControlSocket); err != nil {
		return false
	}
	var current, initial unix.Stat_t
	if unix.Stat("/proc/thread-self/ns/net", &current) != nil || unix.Stat("/proc/1/ns/net", &initial) != nil {
		return false
	}
	return current.Dev == initial.Dev && current.Ino == initial.Ino
}

// wait blocks until udevd has processed the "add" event of every interface, or
// timeout passes, and releases the subscription either way. A timeout is not an
// error: udev may be slow or have lost the event, and the repair pass restores
// anything udev changes later.
func (s *tcUdevSettle) wait(timeout time.Duration) {
	if s == nil {
		return
	}
	defer s.close()
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 16<<10)
	for len(s.pending) > 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		pollFDs := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(pollFDs, int(remaining/time.Millisecond)+1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		for len(s.pending) > 0 {
			n, _, err := unix.Recvfrom(s.fd, buffer, 0)
			if err != nil {
				// ENOBUFS reports that older events were dropped; the socket
				// still holds newer ones.
				if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
					continue
				}
				break
			}
			if interfaceName, added := tcUdevAddedInterface(buffer[:n]); added {
				delete(s.pending, interfaceName)
			}
		}
	}
}

func (s *tcUdevSettle) close() {
	if s == nil || s.fd < 0 {
		return
	}
	_ = unix.Close(s.fd)
	s.fd = -1
}

// tcUdevAddedInterface returns the network interface a libudev monitor message
// reports as added. The message starts with systemd's monitor_netlink_header:
// the "libudev" prefix, a big-endian magic, then the native-endian header size,
// properties offset and properties length, followed by filter hashes. The
// properties are NUL-separated KEY=value strings.
func tcUdevAddedInterface(message []byte) (string, bool) {
	if len(message) < tcUdevMonitorHeaderSize || !bytes.HasPrefix(message, tcUdevMonitorPrefix) {
		return "", false
	}
	if binary.BigEndian.Uint32(message[8:12]) != tcUdevMonitorMagic {
		return "", false
	}
	offset := uint64(binary.NativeEndian.Uint32(message[16:20]))
	length := uint64(binary.NativeEndian.Uint32(message[20:24]))
	if offset < tcUdevMonitorHeaderSize || offset+length > uint64(len(message)) {
		return "", false
	}
	var action, subsystem, interfaceName string
	for _, property := range bytes.Split(message[offset:offset+length], []byte{0}) {
		key, value, found := bytes.Cut(property, []byte{'='})
		if !found {
			continue
		}
		switch string(key) {
		case "ACTION":
			action = string(value)
		case "SUBSYSTEM":
			subsystem = string(value)
		case "INTERFACE":
			interfaceName = string(value)
		}
	}
	if action != "add" || subsystem != "net" || interfaceName == "" {
		return "", false
	}
	return interfaceName, true
}
