//go:build with_ebpf && linux && ebpf_integration

package runtime

import (
	"os"
	goRuntime "runtime"
	"testing"
	"time"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/netlink"
)

// TestTCDeliveryLinkSurvivesUdev creates an isolated delivery link from the
// host's own network namespace, where udevd configures every new interface:
// systemd's default link policy replaces kernel-generated MAC addresses and its
// sysctl rule rewrites the interface's settings. Once creation returns, udev
// must have nothing left to change on the host end: the pair stays healthy and
// the host end keeps the address and MTU the runtime created it with.
//
// The netns tests cannot cover this, because udevd never sees the devices of
// another network namespace. It adds a veth to the host while it runs, so it
// only runs on request.
func TestTCDeliveryLinkSurvivesUdev(t *testing.T) {
	if os.Getenv("SING_EBPF_HOST_UDEV") != "1" {
		t.Skip("set SING_EBPF_HOST_UDEV=1 to create links in the host network namespace")
	}
	goRuntime.LockOSThread()
	defer goRuntime.UnlockOSThread()
	if !tcUdevManagesNetworkNamespace() {
		t.Skip("udevd does not manage this network namespace")
	}
	policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{Local: commonEBPF.ActionScope{Default: commonEBPF.DecisionIntercept}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{ListenerPort: 65530, EnableLocal: true, EnableIPv4: true,
		EnableTCP: true, EnableUDP: true, Policy: policy, AssignmentCapacity: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	n, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	const priority = 2
	dataPlane := &tcDataPlane{backend: backend, namespace: n, priority: priority, replyMTU: 1500}
	delivery, err := dataPlane.createIsolatedTCDeliveryLink()
	if err != nil {
		t.Fatalf("create the delivery link: %v", err)
	}
	defer func() {
		if closeErr := delivery.Close(); closeErr != nil {
			t.Errorf("close the delivery link: %v", closeErr)
		}
	}()
	created := delivery.redirect.Attrs()
	address, mtu := append([]byte(nil), created.HardwareAddr...), created.MTU
	// udevd is done with the host end; a writer it started late would land
	// well within this.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		healthy, healthErr := delivery.healthyIsolated(priority)
		if healthErr != nil {
			t.Fatalf("check the delivery link: %v", healthErr)
		}
		current, linkErr := netlink.LinkByName(delivery.redirectName)
		if linkErr != nil {
			t.Fatalf("find the host end: %v", linkErr)
		}
		if !healthy || current.Attrs().HardwareAddr.String() != created.HardwareAddr.String() || current.Attrs().MTU != mtu {
			t.Fatalf("udev changed the delivery link after creation: healthy %v, host end address %s (created %x), MTU %d (created %d)",
				healthy, current.Attrs().HardwareAddr, address, current.Attrs().MTU, mtu)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
