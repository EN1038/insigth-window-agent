package app

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/quarantine"
	"github.com/sosecure/insite-agent/internal/runtime"
	"github.com/sosecure/insite-agent/internal/scanrun"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
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
			out.LocalCount = len(idx.Files)
			out.UpdatedAt = idx.UpdatedAt
		}
	}
	if h.Settings != nil {
		if out.LocalCount == 0 {
			if n, err := strconv.Atoi(h.Settings.Get(settings.KeyLocalRulesCount, "0")); err == nil {
				out.LocalCount = n
			}
		}
		// Prefer server file count (unique_files / pack files), not rule_names.
		serverFiles := 0
		if n, err := strconv.Atoi(h.Settings.Get(settings.KeyServerRuleFilesCount, "0")); err == nil {
			serverFiles = n
		}
		if serverFiles == 0 {
			if n, err := strconv.Atoi(h.Settings.Get(settings.KeyServerRulesCount, "0")); err == nil {
				// Legacy builds stored rule_names (~10k) in this key; ignore absurd values
				// until the next TI sync writes real pack/file counts.
				if n > 0 && n < 5000 {
					serverFiles = n
				}
			}
		}
		out.ServerCount = serverFiles
		out.BehindServer = out.ServerCount > 0 && out.LocalCount < out.ServerCount
	}
	return out
}

func (h *Host) SsdeepInfo() ipc.SsdeepInfoResponse {
	out := ipc.SsdeepInfoResponse{
		Enabled:   h.Settings != nil && h.Settings.GetBool(settings.KeySsdeepEnabled),
		Version:   "",
		Threshold: "85",
	}
	if h.Settings != nil {
		out.Version = h.Settings.Get(settings.KeySsdeepDBVersion, "")
		out.Threshold = h.Settings.Get(settings.KeySsdeepThreshold, "85")
	}
	store := ssdeepscan.NewStore(h.BaseDir)
	if idx, err := store.LoadIndex(); err == nil && idx != nil {
		out.Total = idx.Total
		out.UpdatedAt = idx.UpdatedAt
		out.Shards = len(idx.Blocks)
		if out.Total == 0 {
			for _, n := range idx.Blocks {
				out.Total += n
			}
		}
		if out.Shards == 0 {
			// Fall back to counting sealed shard files on disk.
			if entries, err := os.ReadDir(filepath.Join(h.BaseDir, "Data", "ssdeep", "shards")); err == nil {
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".shardenc") {
						out.Shards++
					}
				}
			}
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

func (h *Host) ScanRunFiles(runID string, offset, limit int) (rows []ipc.ScanRunFile, total int) {
	sr := h.ScanRuntime()
	if sr == nil || sr.Manager == nil || sr.Manager.ScanRuns == nil {
		return nil, 0
	}
	recs, tot, err := sr.Manager.ScanRuns.List(runID, offset, limit)
	if err != nil {
		return nil, 0
	}
	recs = scanrun.SortInfectedFirst(recs)
	out := make([]ipc.ScanRunFile, 0, len(recs))
	for _, r := range recs {
		out = append(out, ipc.ScanRunFile{
			Path:      r.Path,
			Result:    r.Result,
			Rule:      r.Rule,
			Engine:    r.Engine,
			Score:     r.Score,
			ScannedAt: r.ScannedAt,
		})
	}
	return out, tot
}
