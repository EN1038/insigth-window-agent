//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW     = kernel32.NewProc("CreateMutexW")
	procCloseHandle      = kernel32.NewProc("CloseHandle")
	procGetLastError     = kernel32.NewProc("GetLastError")
	errorAlreadyExists   = uintptr(183) // ERROR_ALREADY_EXISTS
	uiSingletonMutexName = "Local\\SOSECURE_Threat_inSight_UI"
)

// tryAcquireUISingleton returns false if another UI instance already owns the mutex.
// Caller must call the returned release function when the UI exits.
func tryAcquireUISingleton() (release func(), ok bool) {
	name, err := syscall.UTF16PtrFromString(uiSingletonMutexName)
	if err != nil {
		return func() {}, true
	}
	handle, _, _ := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return func() {}, true
	}
	last, _, _ := procGetLastError.Call()
	if last == errorAlreadyExists {
		_, _, _ = procCloseHandle.Call(handle)
		return func() {}, false
	}
	return func() {
		_, _, _ = procCloseHandle.Call(handle)
	}, true
}
