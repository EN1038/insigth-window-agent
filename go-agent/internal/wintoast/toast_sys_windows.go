//go:build windows

package wintoast

import "syscall"

func hiddenPowerShellAttr() *syscall.SysProcAttr {
	// CREATE_NO_WINDOW — avoid a black PowerShell flash behind the toast.
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
