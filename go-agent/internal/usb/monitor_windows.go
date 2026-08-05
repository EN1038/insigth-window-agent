//go:build windows

package usb

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
)

const driveRemovable = 2

type Monitor struct {
	manager  *scan.Manager
	settings *settings.Store
	mu       sync.Mutex
	known    map[string]bool
}

func New(manager *scan.Manager, st *settings.Store) *Monitor {
	return &Monitor{
		manager:  manager,
		settings: st,
		known:    map[string]bool{},
	}
}

func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	m.snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.poll()
		}
	}
}

func (m *Monitor) snapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known = listRemovableDrives()
}

func (m *Monitor) poll() {
	if !m.settings.GetBool(settings.KeyUSBProtection) {
		return
	}
	current := listRemovableDrives()
	m.mu.Lock()
	defer m.mu.Unlock()
	for drive := range current {
		if !m.known[drive] {
			// Only mark known after a scan is accepted; retry while busy.
			if m.manager.StartCustomScan(drive) {
				m.known[drive] = true
			}
		}
	}
	for drive := range m.known {
		if !current[drive] {
			delete(m.known, drive)
		}
	}
}

func listRemovableDrives() map[string]bool {
	out := map[string]bool{}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDriveType := kernel32.NewProc("GetDriveTypeW")
	for _, letter := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		root := string(letter) + `:\`
		if _, err := os.Stat(root); err != nil {
			continue
		}
		p, _ := syscall.UTF16PtrFromString(root)
		t, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(p)))
		if uint32(t) == driveRemovable {
			out[root] = true
		}
	}
	return out
}
