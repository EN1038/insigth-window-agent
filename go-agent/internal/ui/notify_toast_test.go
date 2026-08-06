//go:build windows

package ui

import "testing"

func TestShouldTrayToast(t *testing.T) {
	if !shouldTrayToast("Scan finished. Checked 10 file(s). No threats found.") {
		t.Fatal("expected scan complete toast")
	}
	if shouldTrayToast("Downloading YARA rules (1 of 3): pack.yar") {
		t.Fatal("progress should not toast")
	}
	if shouldTrayToast("Waiting for YARA rule packs from Center…") {
		t.Fatal("waiting should not toast")
	}
	if !shouldTrayToast("Threat intelligence updated. Downloaded 2 YARA rule file(s).") {
		t.Fatal("expected TI toast")
	}
}

func TestTrayToastTitle(t *testing.T) {
	if got := trayToastTitle("Scan finished. Checked 3 file(s), found 1 threat(s)."); got != "Threat detected" {
		t.Fatalf("got %q", got)
	}
	if got := trayToastTitle("Scan finished. Checked 3 file(s). No threats found."); got != "Scan complete" {
		t.Fatalf("got %q", got)
	}
	if got := trayToastTitle("Threat intelligence updated. Downloaded 1 YARA rule file(s)."); got != "Threat intelligence" {
		t.Fatalf("got %q", got)
	}
}
