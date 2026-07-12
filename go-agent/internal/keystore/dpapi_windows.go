//go:build windows

package keystore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectLocalMachine uses Windows DPAPI with LocalMachine scope.
func ProtectLocalMachine(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	in := windows.DataBlob{
		Size: uint32(len(plain)),
		Data: &plain[0],
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	return copyBlob(&out), nil
}

// UnprotectLocalMachine uses Windows DPAPI with LocalMachine scope.
func UnprotectLocalMachine(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("empty blob")
	}
	in := windows.DataBlob{
		Size: uint32(len(protected)),
		Data: &protected[0],
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))

	return copyBlob(&out), nil
}

func copyBlob(b *windows.DataBlob) []byte {
	if b == nil || b.Data == nil || b.Size == 0 {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, (*[1 << 30]byte)(unsafe.Pointer(b.Data))[:b.Size:b.Size])
	return out
}

