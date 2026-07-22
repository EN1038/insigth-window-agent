package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/install"
	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/runtime"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/snapshot"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

type Host struct {
	BaseDir  string
	Config   *config.AgentConfig
	Settings *settings.Store
	Snapshot *snapshot.Store
	Rules    *rules.Store
	History  *history.Store
	Runner   *runtime.Runner
	API      *api.Client
	IPC      *ipc.Server

	mu       sync.RWMutex
	loggedIn bool
}

func NewHost(baseDir string) (*Host, error) {
	_ = install.SecureLocalData(baseDir, config.InstallDir())

	st := settings.New(baseDir)
	if err := st.Load(); err != nil {
		return nil, err
	}
	snap := snapshot.New(baseDir)
	_ = snap.Load()
	hist := history.New(baseDir)
	ruleStore := rules.New(baseDir)
	// If the server does not provide rules yet, seed from legacy Engine\Yara on dev/test machines.
	if idx, err := ruleStore.LoadIndex(); err == nil && idx != nil && len(idx.Files) == 0 {
		candidates := []string{
			`C:\Web\insite_old\insite\Engine\Yara`,                  // dev workspace (this repo)
			filepath.Join(config.InstallDir(), "Engine", "Yara"),   // installed legacy beside exe (if present)
		}
		for _, legacy := range candidates {
			if _, err := os.Stat(legacy); err != nil {
				continue
			}
			if n, err := ruleStore.ImportDir(legacy, 0, "legacy"); err == nil && n > 0 {
				st.Set(settings.KeyRulesVersion, "legacy")
				_ = st.Save()
				_ = hist.Append("rules.legacy", fmt.Sprintf("imported legacy YARA rules (%d files)", n), map[string]any{
					"src": legacy,
				})
				break
			} else if err != nil {
				_ = hist.Append("rules.error", "legacy import: "+err.Error(), map[string]any{"src": legacy})
			}
		}
	}

	if n, err := ssdeepscan.SealBundledSignatures(baseDir, config.InstallDir()); err != nil {
		_ = hist.Append("ssdeep.error", "bundled seal: "+err.Error(), nil)
	} else if n > 0 {
		st.Set(settings.KeySsdeepBundledTotal, fmt.Sprintf("%d", n))
		_ = st.Save()
		_ = hist.Append("ssdeep.bundled", fmt.Sprintf("sealed bundled ssdeep signatures (%d)", n), nil)
	}

	cfg, _ := config.Load(baseDir)
	var apiClient *api.Client
	if cfg != nil {
		apiClient = api.New(cfg)
	}

	runner := runtime.New(baseDir, cfg, st, snap, ruleStore, hist)
	h := &Host{
		BaseDir:  baseDir,
		Config:   cfg,
		Settings: st,
		Snapshot: snap,
		Rules:    ruleStore,
		History:  hist,
		Runner:   runner,
		API:      apiClient,
	}
	h.IPC = ipc.NewServer(h)
	return h, nil
}

func (h *Host) Start(ctx context.Context) error {
	go func() { _ = h.Runner.Run(ctx) }()
	return h.IPC.Listen(ctx, ipc.DefaultAddr)
}

func (h *Host) ReloadConfig(cfg *config.AgentConfig) error {
	if err := config.Save(h.BaseDir, cfg); err != nil {
		return err
	}
	h.mu.Lock()
	h.Config = cfg
	if cfg != nil {
		h.API = api.New(cfg)
	}
	h.mu.Unlock()
	h.Runner.ReloadConfig(cfg)
	return nil
}

func (h *Host) IsLoggedIn() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.loggedIn
}

func (h *Host) SetLoggedIn(v bool) {
	h.mu.Lock()
	h.loggedIn = v
	h.mu.Unlock()
}

func (h *Host) TestConnection() bool {
	h.mu.RLock()
	apiClient := h.API
	h.mu.RUnlock()
	if apiClient == nil {
		return false
	}
	resp, _, err := apiClient.AgentOnlineTimestamp(false)
	return err == nil && resp != nil && resp.StatusCode == 200
}

func (h *Host) Login(email, password string) (bool, string, string) {
	h.mu.RLock()
	apiClient := h.API
	h.mu.RUnlock()
	if apiClient == nil {
		return false, "missing server config", ""
	}
	resp, _, err := apiClient.LoginAgent(email, password)
	if err != nil {
		return false, err.Error(), ""
	}
	if resp.StatusCode != 200 {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("login failed (status %d)", resp.StatusCode)
		}
		return false, msg, ""
	}
	h.SetLoggedIn(true)
	_, _, _ = apiClient.AgentOnlineTimestamp(true)
	agentID := h.Settings.Get("agent_id", "")
	return true, "", agentID
}

func (h *Host) Logout() {
	h.SetLoggedIn(false)
}

func (h *Host) PushSettingsToServer() {
	h.mu.RLock()
	apiClient := h.API
	h.mu.RUnlock()
	if apiClient == nil {
		return
	}
	usb := 0
	rtp := 0
	if h.Settings.GetBool(settings.KeyUSBProtection) {
		usb = 1
	}
	if h.Settings.GetBool(settings.KeyRealtimeShield) {
		rtp = 1
	}
	batch := h.Settings.Get(settings.KeyBatchJobEveryDay, "02:00")
	_, _, _ = apiClient.UpdateConfig(batch, rtp, usb)
}
