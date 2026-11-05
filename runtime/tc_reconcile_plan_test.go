//go:build with_ebpf && (linux || android)

package runtime

import "testing"

func TestOrderedTCAttachmentNamesLocalFirst(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"wlan2": {},
		"eth0":  {},
		"wlan0": {},
	}
	got := orderedTCAttachmentNames("wlan0", desired)
	want := []string{"wlan0", "eth0", "wlan2"}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}

func TestOrderedTCAttachmentNamesWithoutLocalTarget(t *testing.T) {
	desired := map[string]tcAttachmentState{"wlan2": {}, "eth0": {}}
	got := orderedTCAttachmentNames("", desired)
	if len(got) != 2 || got[0] != "eth0" || got[1] != "wlan2" {
		t.Fatalf("names = %v, want [eth0 wlan2]", got)
	}
}
