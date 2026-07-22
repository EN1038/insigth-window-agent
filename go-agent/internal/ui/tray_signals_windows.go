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

func uiSignalPath(name string) string {
	return filepath.Join(config.DataBaseDir(), "Data", name)
}

func requestUIShow() error {
	p := uiSignalPath(uiShowSignal)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	return os.WriteFile(p, []byte(time.Now().Format(time.RFC3339Nano)), 0o600)
}

func requestUIQuit() error {
	p := uiSignalPath(uiQuitSignal)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
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
