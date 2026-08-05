//go:build windows

package login

import (
	"context"
	"sync"
	"time"

	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/winuser"
)

// Monitor starts a quick scan when an interactive Windows session becomes active
// (user sign-in / unlock to Active) while auto_scan_on_login is enabled.
//
// Sessions that are already active when the agent starts are recorded but not
// scanned — otherwise first install / service start would look like an unwanted
// "auto scan on login" even when the user only just opened the UI.
type Monitor struct {
	manager  *scan.Manager
	settings *settings.Store
	mu       sync.Mutex
	scanned  map[uint32]bool
	seeded   bool
}

func New(manager *scan.Manager, st *settings.Store) *Monitor {
	return &Monitor{
		manager:  manager,
		settings: st,
		scanned:  map[uint32]bool{},
	}
}

func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	m.seedActiveSessions()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.poll()
		}
	}
}

// seedActiveSessions marks current interactive sessions as already seen without
// starting a scan (covers reboot / first service start while user is logged in).
func (m *Monitor) seedActiveSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range winuser.ActiveSessionIDs() {
		m.scanned[id] = true
	}
	m.seeded = true
}

func (m *Monitor) poll() {
	if m.settings == nil || m.manager == nil {
		return
	}
	if !m.settings.GetBool(settings.KeyAutoScanOnLogin) {
		return
	}

	active := winuser.ActiveSessionIDs()
	activeSet := make(map[uint32]bool, len(active))
	for _, id := range active {
		activeSet[id] = true
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.seeded {
		for _, id := range active {
			m.scanned[id] = true
		}
		m.seeded = true
		return
	}

	// Drop sessions that logged off so a later sign-in can scan again.
	for id := range m.scanned {
		if !activeSet[id] {
			delete(m.scanned, id)
		}
	}

	for _, id := range active {
		if m.scanned[id] {
			continue
		}
		if m.manager.IsScanning() {
			// Retry next tick; do not mark scanned yet.
			return
		}
		if !m.manager.StartLoginQuickScan() {
			return
		}
		m.scanned[id] = true
		if m.manager.History != nil {
			_ = m.manager.History.Append("scan.login", "auto scan on login", map[string]any{
				"session_id": id,
			})
		}
		// One quick scan covers all interactive profiles; mark remaining new sessions too.
		for _, other := range active {
			m.scanned[other] = true
		}
		return
	}
}
