//go:build with_ebpf && (linux || android)

package core

import (
	"errors"
	"net/netip"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	mapLookupAndDeleteUnknown int32 = iota
	mapLookupAndDeleteSupported
	mapLookupAndDeleteUnsupported
)

func (b *CgroupBackend) LookupOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, false)
}

func (b *CgroupBackend) TakeOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, true)
}

func (b *CgroupBackend) lookupOriginal(
	protocol uint8,
	listenerDestination netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestinationValue
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	if deleteAfterLookup {
		err = b.takeMapElement(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	} else {
		err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) RecoverUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	var original originalDestinationValue
	consumed, err := b.takeUDPRecoveryElement(&key, &original)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup recoverable UDP original destination")
	}
	recoveryOriginal := original
	if err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&key),
		unsafe.Pointer(&original),
		bpfNoExist,
	); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "restore UDP original destination"),
			)
		}
		var existing originalDestinationValue
		if err = lookupMap(b.udpRedirectMapFD, unsafe.Pointer(&key), unsafe.Pointer(&existing)); err != nil {
			return OriginalDestination{}, b.rollbackConsumedUDPRecovery(
				&key,
				&recoveryOriginal,
				consumed,
				E.Cause(err, "lookup concurrently restored UDP original destination"),
			)
		}
		original = existing
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) takeUDPRecoveryElement(
	key *listenerLookupKey,
	original *originalDestinationValue,
) (bool, error) {
	if b.udpRecoveryConsumeMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(
			b.udpRecoveryMapFD,
			unsafe.Pointer(key),
			unsafe.Pointer(original),
		)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteSupported)
			return err == nil, err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return false, err
		}
		b.udpRecoveryConsumeMode.Store(mapLookupAndDeleteUnsupported)
	}
	// A lookup+delete fallback could remove a newer kernel update between the
	// two syscalls. Preserve the LRU entry on kernels without atomic support.
	err := lookupMap(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
	)
	return false, err
}

func (b *CgroupBackend) rollbackConsumedUDPRecovery(
	key *listenerLookupKey,
	original *originalDestinationValue,
	consumed bool,
	recoveryErr error,
) error {
	if !consumed {
		return recoveryErr
	}
	err := updateMapWithFlags(
		b.udpRecoveryMapFD,
		unsafe.Pointer(key),
		unsafe.Pointer(original),
		bpfNoExist,
	)
	if err == nil || errors.Is(err, unix.EEXIST) {
		return recoveryErr
	}
	return E.Errors(recoveryErr, E.Cause(err, "restore consumed UDP recovery state"))
}

func (b *CgroupBackend) RecoverConnectedUDPOriginal(listenerDestination netip.AddrPort) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	listener, err := makeListenerLookupKey(ProtocolUDP, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	b.udpRecoveryAccess.Lock()
	defer b.udpRecoveryAccess.Unlock()
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	if b.runtime.socket_release_supported {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP LRU recovery is disabled")
	}
	var reverse udpTokenReverseValue
	if err = lookupMap(
		b.runtime.udp_token_reverse_map_fd,
		unsafe.Pointer(&listener),
		unsafe.Pointer(&reverse),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup connected UDP token reverse index")
	}
	cookie := reverse.SocketCookie
	if cookie == 0 {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "invalid connected UDP token reverse index")
	}
	if reverse.NetworkGeneration != b.networkGeneration {
		return OriginalDestination{}, E.New("connected UDP token belongs to stale network generation")
	}
	var verifiedToken listenerLookupKey
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "verify connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	peerKey := udpPeerKey{SocketCookie: cookie}
	var peer udpPeerValue
	if err = lookupMap(
		b.runtime.udp_peer_map_fd,
		unsafe.Pointer(&peerKey),
		unsafe.Pointer(&peer),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup connected UDP peer state")
	}
	original, err := originalDestinationFromUDPPeer(cookie, peer)
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "validate connected UDP peer state")
	}
	if original.Family != listener.Family {
		return OriginalDestination{}, E.New(
			"connected UDP token and peer family mismatch: token=", listener.Family,
			", peer=", original.Family,
		)
	}
	if err = lookupMap(
		b.runtime.udp_token_map_fd,
		unsafe.Pointer(&cookie),
		unsafe.Pointer(&verifiedToken),
	); err != nil {
		return OriginalDestination{}, E.Cause(err, "revalidate connected UDP token state")
	}
	if verifiedToken != listener {
		return OriginalDestination{}, E.Cause(unix.ENOENT, "connected UDP token changed during recovery")
	}
	err = updateMapWithFlags(
		b.udpRedirectMapFD,
		unsafe.Pointer(&listener),
		unsafe.Pointer(&original),
		bpfNoExist,
	)
	if errors.Is(err, unix.EEXIST) {
		var existing originalDestinationValue
		if lookupErr := lookupMap(
			b.udpRedirectMapFD,
			unsafe.Pointer(&listener),
			unsafe.Pointer(&existing),
		); lookupErr != nil {
			return OriginalDestination{}, E.Cause(lookupErr, "verify concurrently restored connected UDP redirect")
		}
		if existing != original {
			return OriginalDestination{}, E.New("connected UDP redirect token was concurrently claimed")
		}
		err = nil
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "restore connected UDP redirect state")
	}
	return originalDestinationFromValue(original)
}

func (b *CgroupBackend) ReserveUDPReplyRedirect(
	destination netip.AddrPort,
	listenerPort uint16,
) (netip.Addr, error) {
	if b == nil {
		return netip.Addr{}, errBackendClosed
	}
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().IsUnspecified() {
		return netip.Addr{}, E.New("invalid UDP reply source: ", destination)
	}
	if listenerPort == 0 {
		return netip.Addr{}, E.New("invalid UDP redirect listener port")
	}
	var original originalDestinationValue
	original.Protocol = ProtocolUDP
	original.Port = destination.Port()
	if err := encodeAddress(&original.Family, &original.Addr, destination.Addr()); err != nil {
		return netip.Addr{}, E.Cause(err, "encode UDP reply source")
	}

	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return netip.Addr{}, errBackendClosed
	}
	prefix := b.redirectIPv4
	if destination.Addr().Is6() {
		prefix = b.redirectIPv6
	}
	if !prefix.IsValid() {
		return netip.Addr{}, E.New("UDP reply source address family is not enabled: ", destination)
	}
	for attempt := 0; attempt < userspaceReplyTokenAttempts; {
		sequence := b.udpReplyTokenSequence.Add(1)
		token, valid := userspaceReplyToken(prefix, sequence)
		if !valid {
			continue
		}
		attempt++
		key, err := makeListenerLookupKey(ProtocolUDP, netip.AddrPortFrom(token, listenerPort))
		if err != nil {
			return netip.Addr{}, err
		}
		err = updateMapWithFlags(
			b.udpRedirectMapFD,
			unsafe.Pointer(&key),
			unsafe.Pointer(&original),
			bpfNoExist,
		)
		if err == nil {
			return token, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return netip.Addr{}, E.Cause(err, "reserve UDP reply redirect")
		}
	}
	return netip.Addr{}, E.New("reserve UDP reply redirect: token attempts exhausted")
}

func (b *CgroupBackend) takeMapElement(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if b.lookupAndDeleteMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(mapFD, key, value)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.lookupAndDeleteMode.Store(mapLookupAndDeleteSupported)
			return err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return err
		}
		b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	}
	// Do not emulate LOOKUP_AND_DELETE with two syscalls. A concurrent BPF
	// update can replace the value between them, causing userspace to delete a
	// newer redirect. The maps are bounded/LRU, so retaining the value is safer
	// than corrupting a live flow; the normal cleanup path will reclaim it.
	return lookupMap(mapFD, key, value)
}

func mapLookupAndDeleteUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) DeleteRedirect(protocol uint8, listenerDestination netip.AddrPort) error {
	if b == nil {
		return errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	if protocol == ProtocolUDP && b.udpFlowMapFD >= 0 {
		var original originalDestinationValue
		lookupErr := lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
		if lookupErr == nil {
			if recoveryErr := updateMap(
				b.udpRecoveryMapFD,
				unsafe.Pointer(&key),
				unsafe.Pointer(&original),
			); recoveryErr != nil {
				return E.Cause(recoveryErr, "retain recoverable UDP original destination")
			}
		}
		if lookupErr == nil && original.SocketCookie != 0 {
			flowKey := makeUDPFlowKey(original)
			flowErr := deleteMap(b.udpFlowMapFD, unsafe.Pointer(&flowKey))
			if flowErr != nil && !errors.Is(flowErr, unix.ENOENT) {
				return E.Cause(flowErr, "delete UDP flow cache")
			}
		} else if lookupErr != nil && !errors.Is(lookupErr, unix.ENOENT) {
			return E.Cause(lookupErr, "lookup UDP flow cache key")
		}
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	return nil
}

func (b *CgroupBackend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMapFD, nil
	case ProtocolUDP:
		return b.udpRedirectMapFD, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}
