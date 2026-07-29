package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/keystore"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/snapshot"
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

const (
	keyAgentID        = "agent_id"
	keyDataInfoSent   = "data_info_sent"
	keyApproved       = "approved"
	keyLastApproveChk = "last_approve_check"
	keyLastConfigSync = "last_config_sync"
	keyLastRulesSync  = "last_rules_sync"
)

type Runner struct {
	BaseDir  string
	Config   *config.AgentConfig
	Settings *settings.Store
	Snapshot *snapshot.Store
	Rules    *rules.Store
	API      *api.Client
	History  *history.Store

	mu                  sync.Mutex
	lastApprovalRaw     json.RawMessage
	postApprovalStarted bool
	scanStarted         bool
	Scan                *ScanRuntime

	runCtx         context.Context
	configReady    chan struct{}
	approvalCancel context.CancelFunc
	heartbeatCancel context.CancelFunc
}

func New(baseDir string, cfg *config.AgentConfig, st *settings.Store, snap *snapshot.Store, ruleStore *rules.Store, h *history.Store) *Runner {
	var cli *api.Client
	if cfg != nil {
		keystore.SetActiveSiteKey(cfg.SiteKey)
		cli = api.New(cfg)
	}
	r := &Runner{
		BaseDir:     baseDir,
		Config:      cfg,
		Settings:    st,
		Snapshot:    snap,
		Rules:       ruleStore,
		API:         cli,
		History:     h,
		configReady: make(chan struct{}, 1),
	}
	if cli != nil {
		cli.SetProgressFunc(func(p api.Progress) {
			msg := p.Message
			if msg == "" {
				msg = p.Phase
			}
			if p.Percent > 0 {
				msg = fmt.Sprintf("%s (%.0f%%)", msg, p.Percent)
			}
			_ = r.History.Append("download.progress", msg, map[string]any{
				"phase": p.Phase, "file_index": p.FileIndex, "file_total": p.FileTotal,
				"bytes_read": p.BytesRead, "bytes_total": p.BytesTotal, "percent": p.Percent,
			})
		})
	}
	return r
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Settings == nil {
		return errors.New("missing settings")
	}
	if r.History == nil {
		return errors.New("missing history")
	}

	r.mu.Lock()
	r.runCtx = ctx
	r.mu.Unlock()

	_ = r.History.Append("runtime.start", "service runtime started", nil)

	if err := r.waitUntilConfigured(ctx); err != nil {
		_ = r.History.Append("runtime.stop", "service runtime stopping", nil)
		return err
	}

	if r.standaloneMode() {
		_ = r.History.Append("runtime.standalone", "local scan mode (no server API required)", nil)
		r.Settings.Set(keyApproved, "true")
		_ = r.Settings.Save()
		r.startPostApproval(ctx)
		<-ctx.Done()
		_ = r.History.Append("runtime.stop", "service runtime stopping", nil)
		return ctx.Err()
	}

	r.startOnlineRuntime(ctx)

	<-ctx.Done()
	_ = r.History.Append("runtime.stop", "service runtime stopping", nil)
	return ctx.Err()
}

func (r *Runner) waitUntilConfigured(ctx context.Context) error {
	for {
		if r.standaloneMode() || r.API != nil {
			return nil
		}
		_ = r.History.Append("runtime.warn", "API config missing; waiting for UI/installer", nil)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.configReady:
		}
	}
}

func (r *Runner) startOnlineRuntime(ctx context.Context) {
	if r.API == nil {
		return
	}
	_ = r.History.Append("approve.progress", "starting device registration with server", map[string]any{
		"site_ip": r.ConfigSiteIP(),
	})
	// Always collect + push dataInfo on every online start (IP/hardware can change).
	_ = r.History.Append("approve.progress", "step 1/2: calling dataInfo (collect device info)", nil)
	if ok := r.tryDataInfo(); ok {
		r.Settings.Set(keyDataInfoSent, "true")
		_ = r.Settings.Save()
		_ = r.History.Append("approve.progress", "step 1/2 done: dataInfo sent", nil)
	} else {
		r.Settings.Set(keyDataInfoSent, "false")
		_ = r.Settings.Save()
		_ = r.History.Append("approve.wait", "step 1/2 failed: will retry dataInfo every 10s", map[string]any{
			"ip_private": r.currentIP(),
		})
	}
	r.restartApprovalLoop(ctx)
	r.restartHeartbeatLoop(ctx)
	if r.Settings.GetBool(keyApproved) {
		r.startPostApproval(ctx)
	}
}

func (r *Runner) ConfigSiteIP() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Config == nil {
		return ""
	}
	return r.Config.SiteIP
}

func (r *Runner) restartApprovalLoop(ctx context.Context) {
	r.mu.Lock()
	if r.approvalCancel != nil {
		r.approvalCancel()
	}
	loopCtx, cancel := context.WithCancel(ctx)
	r.approvalCancel = cancel
	r.mu.Unlock()
	go r.approvalLoop(loopCtx)
}

func (r *Runner) restartHeartbeatLoop(ctx context.Context) {
	r.mu.Lock()
	if r.heartbeatCancel != nil {
		r.heartbeatCancel()
	}
	loopCtx, cancel := context.WithCancel(ctx)
	r.heartbeatCancel = cancel
	r.mu.Unlock()
	go r.heartbeatLoop(loopCtx)
}

func (r *Runner) tryDataInfo() bool {
	resp, raw, err := r.API.DataInfo()
	if err != nil {
		_ = r.History.Append("api.error", "dataInfo: "+err.Error(), nil)
		return false
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("dataInfo status=%d body=%s", resp.StatusCode, compact(raw)), map[string]any{
			"ip_private": r.currentIP(),
		})
		return false
	}
	_ = r.History.Append("api.ok", "dataInfo ok", map[string]any{
		"ip_private":  r.currentIP(),
		"device":      r.currentDevice(),
		"system_info": sysinfo.SystemInfo(),
		"os":          sysinfo.OsDescription(),
	})
	return true
}

func (r *Runner) approvalLoop(ctx context.Context) {
	if r.Settings.GetBool(keyApproved) {
		r.startPostApproval(ctx)
		return
	}

	_ = r.History.Append("approve.progress", "step 2/2: checking approval status every 10s", nil)
	r.checkApprovalOnce()

	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r.checkApprovalOnce() {
				return
			}
		}
	}
}

// checkApprovalOnce registers the device if needed and polls server approval.
// Returns true when approved (loop should stop).
func (r *Runner) checkApprovalOnce() bool {
	if r.API == nil {
		_ = r.History.Append("approve.wait", "no API client; open Server Setup and save again", nil)
		return false
	}

	r.Settings.Set(keyLastApproveChk, time.Now().Format(time.RFC3339))
	_ = r.Settings.Save()

	if !r.Settings.GetBool(keyDataInfoSent) {
		_ = r.History.Append("approve.progress", "retry step 1/2: calling dataInfo", nil)
		if r.tryDataInfo() {
			r.Settings.Set(keyDataInfoSent, "true")
			_ = r.Settings.Save()
			_ = r.History.Append("approve.progress", "step 1/2 done: device registered (dataInfo ok)", nil)
		} else {
			_ = r.History.Append("approve.wait", "still waiting: dataInfo not accepted yet (check SiteIP/SiteKey/network)", map[string]any{
				"ip_private": r.currentIP(),
			})
			return false
		}
	}

	_ = r.History.Append("approve.progress", "step 2/2: calling checkedAgentApproved", nil)
	resp, raw, err := r.API.CheckedAgentApproved()
	if err != nil {
		_ = r.History.Append("api.error", "checkedAgentApproved: "+err.Error(), nil)
		return false
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("checkedAgentApproved status=%d body=%s", resp.StatusCode, compact(raw)), nil)
		return false
	}

	r.mu.Lock()
	r.lastApprovalRaw = append(json.RawMessage(nil), resp.Data...)
	r.mu.Unlock()

	approved, agentID := parseApprovedAgentID(resp.Data)
	if approved {
		r.Settings.Set(keyApproved, "true")
		if agentID > 0 {
			r.Settings.Set(keyAgentID, fmt.Sprintf("%d", agentID))
		}
		_ = r.Settings.Save()
		_ = r.History.Append("approve.ok", fmt.Sprintf("approved (agent_id=%d)", agentID), nil)
		r.startPostApproval(r.runCtxOrBackground())
		return true
	}

	r.Settings.Set(keyApproved, "false")
	_ = r.Settings.Save()
	msg := "not approved yet — ask admin to approve this device on the web portal (retry in 10s)"
	if agentID > 0 {
		msg = fmt.Sprintf("agent_id=%d registered but status is pending approval (retry in 10s)", agentID)
	}
	_ = r.History.Append("approve.wait", msg, map[string]any{
		"agent_id": agentID,
	})
	return false
}

func (r *Runner) runCtxOrBackground() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runCtx != nil {
		return r.runCtx
	}
	return context.Background()
}

func (r *Runner) startPostApproval(ctx context.Context) {
	r.mu.Lock()
	if r.postApprovalStarted {
		r.mu.Unlock()
		return
	}
	r.postApprovalStarted = true
	standalone := r.standaloneMode()
	r.mu.Unlock()

	if !standalone {
		go r.postApprovalLoop(ctx)
		go r.configSyncLoop(ctx)
		go r.rulesSyncLoop(ctx)
		go r.ssdeepSyncLoop(ctx)
	}
	r.startScanSubsystem(ctx)
}

func (r *Runner) standaloneMode() bool {
	if r.Settings != nil && r.Settings.GetBool(settings.KeyStandaloneScan) {
		return true
	}
	return r.API == nil
}

func (r *Runner) startScanSubsystem(ctx context.Context) {
	r.mu.Lock()
	if r.scanStarted || r.Snapshot == nil || r.Rules == nil {
		r.mu.Unlock()
		return
	}
	r.scanStarted = true
	r.mu.Unlock()

	r.Scan = NewScanRuntime(r.BaseDir, r.Settings, r.Snapshot, r.API, r.History, r.Rules)
	go r.Scan.Run(ctx)
	_ = r.History.Append("scan.runtime", "scan subsystem started (scheduler, watcher, usb)", nil)
}

func (r *Runner) postApprovalLoop(ctx context.Context) {
	r.runPostApproval()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runPostApproval()
		}
	}
}

func (r *Runner) runPostApproval() {
	if r.API == nil {
		return
	}
	if err := r.syncConfigFromServer(); err == nil {
		r.Settings.Set(keyLastConfigSync, time.Now().Format(time.RFC3339))
		_ = r.Settings.Save()
	}

	r.mu.Lock()
	fallback := append(json.RawMessage(nil), r.lastApprovalRaw...)
	r.mu.Unlock()

	n := r.syncRulesFromServer(fallback)
	if n > 0 {
		r.Settings.Set(keyLastRulesSync, time.Now().Format(time.RFC3339))
		_ = r.Settings.Save()
		if r.Scan != nil {
			r.Scan.RefreshRules()
		}
	}

	if n := r.syncSsdeepFromServer(); n > 0 {
		r.Settings.Set(keyLastSsdeepSync, time.Now().Format(time.RFC3339))
		_ = r.Settings.Save()
	}
}

// SyncThreatIntel pulls config + rules + ssdeep from Center immediately (UI Sync now).
func (r *Runner) SyncThreatIntel() (rulesN, ssdeepN int, err error) {
	if r.API == nil {
		return 0, 0, fmt.Errorf("not connected")
	}
	_ = r.History.Append("download.progress", "Syncing threat intelligence…", map[string]any{"phase": "sync", "percent": 0})
	_ = r.syncConfigFromServer()
	r.mu.Lock()
	fallback := append(json.RawMessage(nil), r.lastApprovalRaw...)
	r.mu.Unlock()
	rulesN = r.syncRulesFromServer(fallback)
	ssdeepN = r.syncSsdeepFromServer()
	if rulesN > 0 {
		r.Settings.Set(keyLastRulesSync, time.Now().Format(time.RFC3339))
		if r.Scan != nil {
			r.Scan.RefreshRules()
		}
	}
	if ssdeepN > 0 {
		r.Settings.Set(keyLastSsdeepSync, time.Now().Format(time.RFC3339))
	}
	_ = r.Settings.Save()
	_ = r.History.Append("download.progress", fmt.Sprintf("Sync done (rules=%d ssdeep=%d)", rulesN, ssdeepN), map[string]any{
		"phase": "sync", "percent": 100, "rules": rulesN, "ssdeep": ssdeepN,
	})
	return rulesN, ssdeepN, nil
}

func (r *Runner) configSyncLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !r.Settings.GetBool(keyApproved) {
				continue
			}
			if err := r.syncConfigFromServer(); err == nil {
				r.Settings.Set(keyLastConfigSync, time.Now().Format(time.RFC3339))
				_ = r.Settings.Save()
			}
		}
	}
}

func (r *Runner) rulesSyncLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !r.Settings.GetBool(keyApproved) {
				continue
			}
			n := r.syncRulesFromServer(nil)
			if n > 0 {
				r.Settings.Set(keyLastRulesSync, time.Now().Format(time.RFC3339))
				_ = r.Settings.Save()
				if r.Scan != nil {
					r.Scan.RefreshRules()
				}
			}
		}
	}
}

func (r *Runner) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()

	r.doHeartbeat(true)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.doHeartbeat(true)
		}
	}
}

func (r *Runner) doHeartbeat(isLogin bool) {
	if r.API == nil {
		return
	}
	resp, raw, err := r.API.AgentOnlineTimestamp(isLogin)
	if err != nil {
		_ = r.History.Append("api.error", "heartbeat: "+err.Error(), nil)
		return
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("heartbeat status=%d body=%s", resp.StatusCode, compact(raw)), nil)
		return
	}
	_ = r.History.Append("heartbeat.ok", "heartbeat ok", nil)
}

func parseApprovedAgentID(data json.RawMessage) (approved bool, agentID int64) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return false, 0
	}
	agentRaw, ok := root["agent"]
	if !ok {
		// Pending responses often return the agent row at the top level.
		agentRaw = data
	}
	var agent struct {
		ID     int64 `json:"id"`
		Status any   `json:"status"`
	}
	if err := json.Unmarshal(agentRaw, &agent); err != nil {
		return false, 0
	}
	status := 0
	switch v := agent.Status.(type) {
	case float64:
		status = int(v)
	case string:
		if v == "1" {
			status = 1
		}
	}
	return status == 1, agent.ID
}

func (r *Runner) ReloadConfig(cfg *config.AgentConfig) {
	r.mu.Lock()
	r.Config = cfg
	if cfg != nil {
		keystore.SetActiveSiteKey(cfg.SiteKey)
		r.API = api.New(cfg)
		r.API.SetProgressFunc(func(p api.Progress) {
			msg := p.Message
			if msg == "" {
				msg = p.Phase
			}
			if p.Percent > 0 {
				msg = fmt.Sprintf("%s (%.0f%%)", msg, p.Percent)
			}
			_ = r.History.Append("download.progress", msg, map[string]any{
				"phase":      p.Phase,
				"file_index": p.FileIndex,
				"file_total": p.FileTotal,
				"bytes_read": p.BytesRead,
				"bytes_total": p.BytesTotal,
				"percent":    p.Percent,
			})
		})
	} else {
		keystore.SetActiveSiteKey("")
		r.API = nil
	}
	runCtx := r.runCtx
	r.mu.Unlock()

	if r.Settings != nil {
		r.Settings.Set(keyDataInfoSent, "false")
		r.Settings.Set(keyApproved, "false")
		r.Settings.Set("agent_id", "")
		_ = r.Settings.Save()
	}

	select {
	case r.configReady <- struct{}{}:
	default:
	}

	// If runtime is already alive, kick dataInfo + approval immediately after Save & Connect.
	if runCtx != nil && cfg != nil && !r.standaloneMode() {
		_ = r.History.Append("config.reload", "server settings saved; registering device", nil)
		r.startOnlineRuntime(runCtx)
	}
}

func compact(b []byte) string {
	if len(b) > 800 {
		return string(b[:800]) + "...(truncated)"
	}
	return string(b)
}

func (r *Runner) currentIP() string {
	return sysinfo.LocalIPv4()
}

func (r *Runner) currentDevice() string {
	return sysinfo.Hostname()
}
