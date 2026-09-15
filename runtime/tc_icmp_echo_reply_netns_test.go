//go:build with_ebpf && (linux || android)

package runtime

import (
	"net"
	"testing"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/netlink"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// setupICMPEchoReplyPingVeth builds a veth pair, an IPv4 ForceIntercept route through
// it, a static neighbor entry for the ForceIntercept target, and clears rp_filter —
// everything an IPv4 icmp_echo_reply local_reply ping test needs before an
// attachment is added, factored out so both the clsact and TCX real-ping
// tests build the exact same network state.
func setupICMPEchoReplyPingVeth(t *testing.T, selfName, peerName, forceInterceptTarget string) netlink.Link {
	t.Helper()
	attributes := netlink.NewLinkAttrs()
	attributes.Name = selfName
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	self, err := netlink.LinkByName(selfName)
	if err != nil {
		t.Fatalf("find veth: %v", err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("find veth peer: %v", err)
	}
	for _, link := range []netlink.Link{self, peer} {
		if err = netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up %s: %v", link.Attrs().Name, err)
		}
	}
	selfAddress := &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 250, 0, 1), Mask: net.CIDRMask(24, 32)}}
	if err = netlink.AddrAdd(self, selfAddress); err != nil {
		t.Fatalf("address the veth: %v", err)
	}
	// The ForceIntercept prefix is otherwise unroutable in this namespace; the local
	// reply mechanism relies on ordinary routing sending the request out the
	// interface the egress classifier watches, the same way it would for a
	// real default route.
	forceInterceptRoute := &netlink.Route{
		LinkIndex: self.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)},
	}
	if err = netlink.RouteAdd(forceInterceptRoute); err != nil {
		t.Fatalf("route the ForceIntercept prefix through the veth: %v", err)
	}
	// The route above is on-link, so the kernel ARPs for the ForceIntercept address
	// before it will queue the packet to this device at all — and nothing
	// answers, since the peer never claims it. A static neighbor entry (any
	// hardware address on the segment does, since the peer is what actually
	// discards the frame after this test's classifier has already consumed
	// it) skips that resolution so the packet reaches the egress classifier
	// immediately instead of sitting in the unresolved-neighbor queue for the
	// duration of this test's deadline.
	neighbor := &netlink.Neigh{
		LinkIndex:    self.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP(forceInterceptTarget),
		HardwareAddr: peer.Attrs().HardwareAddr,
	}
	if err = netlink.NeighAdd(neighbor); err != nil {
		t.Fatalf("add a static neighbor entry for the ForceIntercept target: %v", err)
	}
	// The reply re-enters this box's own receive path with a source address
	// (the ForceIntercept) that nothing on this interface would itself originate from
	// by the kernel's reckoning; strict reverse-path filtering drops it on
	// exactly that basis, the same composition (max(conf.all, conf.<dev>))
	// this whole series' rp_filter fixes exist for. Cleared on both for the
	// same reason createTCDeliveryLink clears both on the real delivery veth.
	for _, name := range []string{"all", selfName} {
		if _, _, err = setTCSysctl(tcInterfaceSysctlPath(name, "rp_filter"), "0"); err != nil {
			t.Fatalf("clear rp_filter for %s: %v", name, err)
		}
	}
	return self
}

// pingICMPEchoReplyTarget sends one real ICMP Echo Request to forceInterceptTarget over
// a fresh raw socket and asserts a real, correctly-formed, correctly-checksummed,
// non-amplifying Echo Reply comes back from it. Returns a non-nil error
// (never a fatal test failure) so callers can also assert the *absence* of a
// reply, e.g. while an attachment is broken on purpose.
func pingICMPEchoReplyTarget(t *testing.T, forceInterceptTarget string, deadline time.Duration) error {
	t.Helper()
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Fatalf("open a raw ICMP socket: %v", err)
	}
	defer conn.Close()

	identifier := 0x1234 + int(time.Now().UnixNano()&0xff)
	sequence := 7
	payload := []byte("force_intercept-icmp-reply-test-payload")
	request := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: identifier, Seq: sequence, Data: payload},
	}
	requestBytes, err := request.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal the echo request: %v", err)
	}

	if err = conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatalf("set a deadline: %v", err)
	}
	if _, err = conn.WriteTo(requestBytes, &net.IPAddr{IP: net.ParseIP(forceInterceptTarget)}); err != nil {
		t.Fatalf("send the echo request: %v", err)
	}

	buffer := make([]byte, 1500)
	replyLength, peerAddress, err := conn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	if replyLength > len(requestBytes) {
		t.Fatalf("reply is %d bytes, longer than the %d-byte request — an amplification, not a reply",
			replyLength, len(requestBytes))
	}
	if addr, ok := peerAddress.(*net.IPAddr); !ok || addr.IP.String() != forceInterceptTarget {
		t.Fatalf("reply source = %v, want it to still carry the ForceIntercept address %s", peerAddress, forceInterceptTarget)
	}

	reply, err := icmp.ParseMessage(1 /* iana.ProtocolICMP */, buffer[:replyLength])
	if err != nil {
		t.Fatalf("parse the reply: %v", err)
	}
	if reply.Type != ipv4.ICMPTypeEchoReply {
		t.Fatalf("reply type = %v, want an echo reply", reply.Type)
	}
	if reply.Code != 0 {
		t.Fatalf("reply code = %d, want 0", reply.Code)
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body = %T, want *icmp.Echo", reply.Body)
	}
	if echo.ID != identifier || echo.Seq != sequence {
		t.Fatalf("reply identifier/sequence = %d/%d, want %d/%d", echo.ID, echo.Seq, identifier, sequence)
	}
	if string(echo.Data) != string(payload) {
		t.Fatalf("reply payload = %q, want %q unchanged", echo.Data, payload)
	}
	if checksum := icmpChecksum(buffer[:replyLength]); checksum != 0 {
		t.Fatalf("reply ICMP checksum does not validate (residual %#04x)", checksum)
	}
	return nil
}

// TestICMPEchoLocalReplyAnswersARealPing is the end-to-end check the rest
// of this feature's tests only approach: a real ICMP Echo Request, built by
// the standard library's own ICMP encoder and sent through a real raw
// socket, crossing a real veth with the real icmp_echo_reply local_reply program
// attached at egress, and a real Echo Reply read back on the same socket —
// not an inspection of Go structs or a kernel-side filter list.
//
// The veth's peer is never touched: the request is answered on the egress
// side before it would ever reach the peer, which is itself part of what
// this test confirms (the request does not continue past this box).
func TestICMPEchoLocalReplyAnswersARealPing(t *testing.T) {
	enterTestNetworkNamespace(t)
	backend := newRealICMPEchoReplyBackend(t)
	t.Cleanup(func() { _ = backend.Close() })

	const forceInterceptTarget = "198.18.0.1"
	self := setupICMPEchoReplyPingVeth(t, "sbicmpr0", "sbicmpr1", forceInterceptTarget)

	const priority = 2 // force clsact; see TestAttachTCInterfaceAddsTheICMPEchoReplyFilterWhenEnabled.
	lock, err := acquireTCInterfaceLock("sbicmpr0", self.Attrs().Index)
	if err != nil {
		t.Fatalf("acquire the interface lock: %v", err)
	}
	attachment, err := attachTCInterfaceWithLock(
		netlink.LinkByName,
		backend,
		"sbicmpr0",
		tcAttachmentState{
			index:   self.Attrs().Index,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{local: true},
		},
		false,
		priority,
		lock,
		true,
	)
	if err != nil {
		t.Fatalf("attach the interface: %v", err)
	}
	t.Cleanup(func() { _ = attachment.Close() })
	if attachment.attachmentType != "clsact" {
		t.Fatalf("attachmentType = %q, want clsact", attachment.attachmentType)
	}

	before, err := backend.ICMPEchoReplyCount()
	if err != nil {
		t.Fatalf("read ICMPEchoReplyCount before: %v", err)
	}
	if err = pingICMPEchoReplyTarget(t, forceInterceptTarget, 5*time.Second); err != nil {
		t.Fatalf("read a reply: %v (the request may have gone to the wire instead of being answered)", err)
	}
	after, err := backend.ICMPEchoReplyCount()
	if err != nil {
		t.Fatalf("read ICMPEchoReplyCount after: %v", err)
	}
	if after != before+1 {
		t.Fatalf("ICMPEchoReplyCount = %d, want %d after one successfully answered ping", after, before+1)
	}
}

// icmpChecksum folds the standard Internet checksum over an ICMP message
// that already carries its own checksum field: a valid message sums to
// exactly 0 (RFC 1071's self-verifying property), independent of what
// icmp.ParseMessage itself checks, which is only that the message is
// well-formed, not that the checksum field is correct.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(b); index += 2 {
		sum += uint32(b[index])<<8 | uint32(b[index+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}
