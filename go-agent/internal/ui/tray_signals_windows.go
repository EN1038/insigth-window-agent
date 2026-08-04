//go:build windows

package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
)

const (
	uiShowSignal = "ui.show"
	uiQuitSignal = "ui.quit"
)

// uiSignalDir is a per-user runtime folder (not the ACL-hardened ProgramData\Data
// tree). Cross-process UI signals (second launch → show, confirm-exit → quit)
// must be writable by the logged-in user.
func uiSignalDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, config.AppFolderName, "runtime")
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

func uiSignalPath(name string) string {
	return filepath.Join(uiSignalDir(), name)
}

func requestUIShow() error {
	p := uiSignalPath(uiShowSignal)
	return os.WriteFile(p, []byte(time.Now().Format(time.RFC3339Nano)), 0o600)
}

func requestUIQuit() error {
	p := uiSignalPath(uiQuitSignal)
	return os.WriteFile(p, []byte(time.Now().Format(time.RFC3339Nano)), 0o600)
}

func consumeUISignal(name string) bool {
	p := uiSignalPath(name)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	_ = os.Remove(p)
	return true
}

func launchConfirmExit() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-mode", "confirm-exit")
	cmd.Dir = filepath.Dir(exe)
	return cmd.Start()
}
