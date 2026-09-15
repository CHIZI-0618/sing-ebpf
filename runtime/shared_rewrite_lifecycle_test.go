//go:build with_ebpf && (linux || android)

package runtime

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/netlink"
)

type sharedCountingCloser struct{ attempts int }

func (c *sharedCountingCloser) Close() error {
	c.attempts++
	return nil
}

func TestSharedRewritePurgeCallbackCanReenterRuntime(t *testing.T) {
	var dataPlane *sharedRewriteDataPlane
	var callbackErr error
	callbackCount := 0
	dataPlane = newSharedRewriteDataPlane(SharedPacketRewriteHooks{
		PurgeUserspaceFlow: func() {
			callbackCount++
			if descriptions := dataPlane.attachmentDescriptions(); len(descriptions) != 0 {
				callbackErr = errors.New("retired attachment remained visible during callback")
				return
			}
			callbackErr = dataPlane.reconcile(nil, nil)
		},
	}, defaultTCPriority)
	dataPlane.attachments["wlan0"] = &sharedRewriteAttachment{interfaceName: "wlan0"}

	done := make(chan error, 1)
	go func() {
		done <- dataPlane.reconcile(nil, nil)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("purge callback deadlocked while re-entering shared runtime")
	}
	if callbackErr != nil {
		t.Fatalf("callback re-entry: %v", callbackErr)
	}
	if callbackCount != 1 {
		t.Fatalf("purge callback count = %d, want 1", callbackCount)
	}
}

func TestSharedRewriteCallbackEventOrder(t *testing.T) {
	var calls []string
	hooks := SharedPacketRewriteHooks{
		PurgeUserspaceFlow: func() { calls = append(calls, "purge") },
		Ready: func(attachments []string) {
			calls = append(calls, "ready:"+attachments[0])
		},
		WarnFlowPurge: func(interfaceName string, err error) {
			calls = append(calls, "warn:"+interfaceName+":"+err.Error())
		},
	}
	var events sharedRewriteCallbackEvents
	events.warnFlowPurge("wlan0", errors.New("failed"))
	events.ready([]string{"wlan1(tcx)"})
	events.purgeUserspaceFlow()
	events.dispatch(hooks)
	want := []string{"warn:wlan0:failed", "ready:wlan1(tcx)", "purge"}
	if len(calls) != len(want) {
		t.Fatalf("callback order = %v, want %v", calls, want)
	}
	for index := range want {
		if calls[index] != want[index] {
			t.Fatalf("callback order = %v, want %v", calls, want)
		}
	}
}

func TestSharedRewriteAttachmentCloseRetainsFailedResources(t *testing.T) {
	filter := &netlink.BpfFilter{}
	interfaceLock := &sharedCountingCloser{}
	detachAttempts := 0
	attachment := &sharedRewriteAttachment{
		ingressFilter: filter,
		lock:          interfaceLock,
		detachFilter: func(*netlink.BpfFilter) error {
			detachAttempts++
			if detachAttempts == 1 {
				return errors.New("injected shared filter detach failure")
			}
			return nil
		},
	}

	if err := attachment.Close(); err == nil {
		t.Fatal("expected injected shared filter detach failure")
	}
	if attachment.ingressFilter != filter {
		t.Fatal("failed detach lost the filter needed for retry")
	}
	if attachment.lock == nil || interfaceLock.attempts != 0 {
		t.Fatal("interface lock was released while a filter was still owned")
	}
	if attachment.IsClosed() {
		t.Fatal("attachment reports closed while it still owns resources")
	}

	if err := attachment.Close(); err != nil {
		t.Fatalf("retry shared attachment close: %v", err)
	}
	if !attachment.IsClosed() {
		t.Fatal("attachment retained resources after successful retry")
	}
	if interfaceLock.attempts != 1 {
		t.Fatalf("interface lock close attempts = %d, want 1", interfaceLock.attempts)
	}
}

func TestSharedRewriteRuntimeCloseRetainsFailedAttachment(t *testing.T) {
	filter := &netlink.BpfFilter{}
	detachAttempts := 0
	attachment := &sharedRewriteAttachment{
		ingressFilter: filter,
		detachFilter: func(*netlink.BpfFilter) error {
			detachAttempts++
			if detachAttempts == 1 {
				return errors.New("injected runtime detach failure")
			}
			return nil
		},
	}
	runtime := &sharedRewriteDataPlane{
		attachments: map[string]*sharedRewriteAttachment{"wlan0": attachment},
	}

	if err := runtime.Close(); err == nil {
		t.Fatal("expected injected runtime detach failure")
	}
	if runtime.IsClosed() {
		t.Fatal("runtime reports closed after losing an attachment cleanup")
	}
	if runtime.attachments["wlan0"] != attachment {
		t.Fatal("runtime lost the attachment needed for cleanup retry")
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("retry shared runtime close: %v", err)
	}
	if !runtime.IsClosed() {
		t.Fatal("runtime remained open after successful cleanup retry")
	}
}
