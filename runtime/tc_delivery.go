//go:build with_ebpf && (linux || android)

package runtime

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// newTCDeliveryHardwareAddress returns a random locally administered unicast
// MAC address for one end of the delivery pair.
//
// The host end is in the network namespace udevd manages. systemd's
// 99-default.link (MACAddressPolicy=persistent) replaces a kernel-generated
// address (NET_ADDR_RANDOM) shortly after the link appears, after the private
// namespace's static neighbor entry was set to it; an address given at creation
// is NET_ADDR_SET, which udev leaves alone. The redirect programs address each
// frame to the private end, which drops a frame for any other MAC as
// PACKET_OTHERHOST, so that end gets an explicit address as well.
func newTCDeliveryHardwareAddress() (net.HardwareAddr, error) {
	address := make(net.HardwareAddr, len(commonEBPF.MACAddress{}))
	if _, err := rand.Read(address); err != nil {
		return nil, err
	}
	address[0] = address[0]&^0x01 | 0x02
	return address, nil
}

func tcDeliveryMACAddress(link netlink.Link) (commonEBPF.MACAddress, bool) {
	var address commonEBPF.MACAddress
	hardwareAddress := link.Attrs().HardwareAddr
	if len(hardwareAddress) != len(address) {
		return address, false
	}
	copy(address[:], hardwareAddress)
	return address, true
}

func nextTCVethNames() (string, string, error) {
	for range 1024 {
		sequence := tcVethSequence.Add(1)
		suffix := fmt.Sprintf("%04x%04x", uint32(os.Getpid())&0xffff, sequence&0xffff)
		redirectName := "sbt" + suffix
		deliveryName := "sbd" + suffix
		if len(redirectName) > 15 || len(deliveryName) > 15 {
			return "", "", E.New("TC eBPF delivery link name exceeds Linux limit")
		}
		_, redirectErr := netlink.LinkByName(redirectName)
		_, deliveryErr := netlink.LinkByName(deliveryName)
		if tcLinkNotFound(redirectErr) && tcLinkNotFound(deliveryErr) {
			return redirectName, deliveryName, nil
		}
		if redirectErr != nil && !tcLinkNotFound(redirectErr) {
			return "", "", redirectErr
		}
		if deliveryErr != nil && !tcLinkNotFound(deliveryErr) {
			return "", "", deliveryErr
		}
	}
	return "", "", E.New("unable to allocate TC eBPF delivery link name")
}

// These settings are applied only inside the caller-owned private namespace.
// Namespace destruction owns their lifetime; no host-global restore list exists.
// tcNamespaceTimeWaitPath bounds TIME_WAIT sockets of the namespace that runs
// it; within a private socket-assignment namespace it is that namespace's own.
const tcNamespaceTimeWaitPath = "/proc/sys/net/ipv4/tcp_max_tw_buckets"

func tcOptionalSysctlUnavailable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, os.ErrInvalid) || errors.Is(err, unix.EROFS)
}

func tcInterfaceSysctlPath(interfaceName, setting string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/" + setting
}

func setTCSysctl(path, value string) (bool, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(current)) == value {
		return false, nil
	}
	if err = os.WriteFile(path, []byte(value), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func (d *tcDeliveryLink) IsClosed() bool {
	return d == nil || d.filter == nil && d.returnFilter == nil && d.redirect == nil && d.delivery == nil
}

func (d *tcDeliveryLink) Close() error {
	if d == nil {
		return nil
	}
	return d.closeIsolated()
}
