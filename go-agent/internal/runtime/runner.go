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
}

func New(baseDir string, cfg *config.AgentConfig, st *settings.Store, snap *snapshot.Store, ruleStore *rules.Store, h *history.Store) *Runner {
	var cli *api.Client
	if cfg != nil {
		cli = api.New(cfg)
	}
	return &Runner{
		BaseDir:  baseDir,
		Config:   cfg,
		Settings: st,
		Snapshot: snap,
		Rules:    ruleStore,
		API:      cli,
		History:  h,
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Settings == nil {
		return errors.New("missing settings")
	}
	if r.History == nil {
		return errors.New("missing history")
	}
	if r.API == nil {
		_ = r.History.Append("runtime.warn", "API config missing; waiting for UI/installer", nil)
		<-ctx.Done()
		return ctx.Err()
	}

	_ = r.History.Append("runtime.start", "service runtime started", nil)

	if !r.Settings.GetBool(keyDataInfoSent) {
		if ok := r.tryDataInfo(); ok {
			r.Settings.Set(keyDataInfoSent, "true")
			_ = r.Settings.Save()
		}
	}

	go r.approvalLoop(ctx)
	go r.heartbeatLoop(ctx)

	if r.Settings.GetBool(keyApproved) {
		r.startPostApproval(ctx)
	}

	<-ctx.Done()
	_ = r.History.Append("runtime.stop", "service runtime stopping", nil)
	return ctx.Err()
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
		"ip_private": r.currentIP(),
		"device":     r.currentDevice(),
	})
	return true
}

func (r *Runner) approvalLoop(ctx context.Context) {
	if r.Settings.GetBool(keyApproved) {
		return
	}

	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Settings.Set(keyLastApproveChk, time.Now().Format(time.RFC3339))
			_ = r.Settings.Save()

			// Ensure device is registered before approval check.
			if !r.Settings.GetBool(keyDataInfoSent) {
				if r.tryDataInfo() {
					r.Settings.Set(keyDataInfoSent, "true")
					_ = r.Settings.Save()
				} else {
					_ = r.History.Append("approve.wait", "waiting for dataInfo registration", map[string]any{
						"ip_private": r.currentIP(),
					})
					continue
				}
			}

			resp, raw, err := r.API.CheckedAgentApproved()
			if err != nil {
				_ = r.History.Append("api.error", "checkedAgentApproved: "+err.Error(), nil)
				continue
			}
			if resp.StatusCode != 200 {
				_ = r.History.Append("api.warn", fmt.Sprintf("checkedAgentApproved status=%d body=%s", resp.StatusCode, compact(raw)), nil)
				continue
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
				r.startPostApproval(ctx)
				return
			}

			r.Settings.Set(keyApproved, "false")
			_ = r.Settings.Save()
			_ = r.History.Append("approve.wait", "waiting for admin approval", nil)
		}
	}
}

func (r *Runner) startPostApproval(ctx context.Context) {
	r.mu.Lock()
	if r.postApprovalStarted {
		r.mu.Unlock()
		return
	}
	r.postApprovalStarted = true
	r.mu.Unlock()

	go r.postApprovalLoop(ctx)
	go r.configSyncLoop(ctx)
	go r.rulesSyncLoop(ctx)
	r.startScanSubsystem(ctx)
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

	r.doHeartbeat(false)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.doHeartbeat(false)
		}
	}
}

func (r *Runner) doHeartbeat(isLogin bool) {
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
		return false, 0
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
	r.Config = cfg
	if cfg != nil {
		r.API = api.New(cfg)
	} else {
		r.API = nil
	}
	if r.Settings != nil {
		r.Settings.Set(keyDataInfoSent, "false")
		r.Settings.Set(keyApproved, "false")
		r.Settings.Set("agent_id", "")
		_ = r.Settings.Save()
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
