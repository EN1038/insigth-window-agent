package app

import (
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/quarantine"
	"github.com/sosecure/insite-agent/internal/runtime"
	"github.com/sosecure/insite-agent/internal/settings"
)

func (h *Host) GetConfig() *config.AgentConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.Config
}

func (h *Host) GetSettings() *settings.Store {
	return h.Settings
}

func (h *Host) GetHistory() *history.Store {
	return h.History
}

func (h *Host) ScanRuntime() *runtime.ScanRuntime {
	return h.Runner.Scan
}

func (h *Host) RulesInfo() ipc.RulesInfoResponse {
	out := ipc.RulesInfoResponse{
		Version: h.Settings.Get(settings.KeyRulesVersion, ""),
	}
	if h.Rules != nil {
		if idx, err := h.Rules.LoadIndex(); err == nil && idx != nil {
			out.Count = len(idx.Files)
			out.UpdatedAt = idx.UpdatedAt
		}
	}
	return out
}

func (h *Host) QuarantineList() []ipc.QuarantineItem {
	qpath := h.Settings.Get(settings.KeyQuarantinePath, "")
	store := quarantine.New(h.BaseDir, qpath)
	if err := store.Load(); err != nil {
		return nil
	}
	items := store.List()
	out := make([]ipc.QuarantineItem, 0, len(items))
	for _, m := range items {
		ts := ""
		if m.IsolatedUnix > 0 {
			ts = time.Unix(m.IsolatedUnix, 0).Format("2006-01-02 15:04")
		}
		out = append(out, ipc.QuarantineItem{
			ID:           m.ID,
			FileName:     m.FileName,
			OriginalPath: m.OriginalPath,
			ThreatType:   m.ThreatType,
			IsolatedAt:   ts,
		})
	}
	return out
}
