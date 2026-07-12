//go:build windows

package install

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// IsAdmin returns true if the current process has admin rights.
func IsAdmin() bool {
	// Easiest reliable check: see if we can open the SCM with full access.
	// Non-admin tokens will fail with access denied.
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return false
	}
	_ = windows.CloseServiceHandle(m)
	return true
}

// DefaultInstallDir is where the installed binary should live for production installs.
func DefaultInstallDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "SOSECURE Threat inSight")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, cErr := io.Copy(out, in)
	closeErr := out.Close()
	if cErr != nil {
		return cErr
	}
	return closeErr
}

// RunElevated relaunches the current executable with UAC prompt (runas).
func RunElevated(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	showCmd := int32(1) // SW_SHOWNORMAL
	return windows.ShellExecute(0, verb, file, params, dir, showCmd)
}

// SetupOneClick installs the service from a stable install directory and optionally launches the UI.
// If launchUI is true, it starts the installed exe in UI mode after installation.
func SetupOneClick(launchUI bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	installDir := DefaultInstallDir()
	targetExe := filepath.Join(installDir, filepath.Base(exe))
	if !strings.EqualFold(exe, targetExe) {
		if err := copyFile(exe, targetExe); err != nil {
			return fmt.Errorf("copy to install dir: %w", err)
		}
		// Run install from the copied binary so the Windows service points to the stable path.
		cmd := exec.Command(targetExe, "-mode", "install")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		if launchUI {
			_ = exec.Command(targetExe, "-mode", "ui").Start()
		}
		return nil
	}

	// Already running from install dir.
	if err := Install(); err != nil {
		return err
	}
	if launchUI {
		_ = exec.Command(targetExe, "-mode", "ui").Start()
	}
	return nil
}

