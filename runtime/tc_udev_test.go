//go:build with_ebpf && linux

package runtime

import (
	"encoding/binary"
	"strings"
	"testing"
)

// udevMonitorMessage builds a message the way udevd's device monitor sends it.
func udevMonitorMessage(properties ...string) []byte {
	payload := []byte(strings.Join(properties, "\x00") + "\x00")
	message := make([]byte, tcUdevMonitorHeaderSize, tcUdevMonitorHeaderSize+len(payload))
	copy(message, tcUdevMonitorPrefix)
	binary.BigEndian.PutUint32(message[8:12], tcUdevMonitorMagic)
	binary.NativeEndian.PutUint32(message[12:16], tcUdevMonitorHeaderSize)
	binary.NativeEndian.PutUint32(message[16:20], tcUdevMonitorHeaderSize)
	binary.NativeEndian.PutUint32(message[20:24], uint32(len(payload)))
	return append(message, payload...)
}

func TestTCUdevAddedInterface(t *testing.T) {
	added := udevMonitorMessage(
		"ACTION=add",
		"DEVPATH=/devices/virtual/net/sbd12340001",
		"SUBSYSTEM=net",
		"INTERFACE=sbd12340001",
		"IFINDEX=42",
		"SEQNUM=1234",
	)
	interfaceName, ok := tcUdevAddedInterface(added)
	if !ok || interfaceName != "sbd12340001" {
		t.Fatalf("tcUdevAddedInterface = %q, %v; want sbd12340001", interfaceName, ok)
	}

	kernelEvent := []byte("add@/devices/virtual/net/sbd12340001\x00ACTION=add\x00SUBSYSTEM=net\x00INTERFACE=sbd12340001\x00")
	truncated := added[:len(added)-12]
	binary.NativeEndian.PutUint32(truncated[20:24], uint32(len(added)))
	badMagic := udevMonitorMessage("ACTION=add", "SUBSYSTEM=net", "INTERFACE=sbd12340001")
	binary.BigEndian.PutUint32(badMagic[8:12], 0)
	for name, message := range map[string][]byte{
		// Only udevd's processed events mean udev has finished with the device.
		"kernel event":    kernelEvent,
		"removal":         udevMonitorMessage("ACTION=remove", "SUBSYSTEM=net", "INTERFACE=sbd12340001"),
		"other subsystem": udevMonitorMessage("ACTION=add", "SUBSYSTEM=queues", "INTERFACE=sbd12340001"),
		"no interface":    udevMonitorMessage("ACTION=add", "SUBSYSTEM=net"),
		"bad magic":       badMagic,
		"truncated":       truncated,
		"header only":     added[:tcUdevMonitorHeaderSize-1],
	} {
		if interfaceName, ok = tcUdevAddedInterface(message); ok {
			t.Errorf("%s: tcUdevAddedInterface = %q, want no interface", name, interfaceName)
		}
	}
}

func TestTCUdevSettleWithoutSubscription(t *testing.T) {
	// A namespace udevd does not manage yields no subscription, and waiting on
	// it must return at once.
	var settle *tcUdevSettle
	settle.wait(tcUdevSettleTimeout)
	settle.close()
}
