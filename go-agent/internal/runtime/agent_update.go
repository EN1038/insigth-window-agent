package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/version"
)

// PendingUpdateFile is written by the main agent and applied by the watchdog.
const PendingUpdateFile = "pending_update.json"

type pendingUpdatePayload struct {
	StagedPath    string `json:"staged_path"`
	SHA256        string `json:"sha256"`
	TargetVersion string `json:"target_version"`
	CurrentVersion string `json:"current_version"`
	RequestedAt   string `json:"requested_at"`
}

func (r *Runner) agentUpdateScheduleLoop(ctx context.Context) {
	r.ensureAutoScheduleDefaults()
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	// Report version once shortly after start (install deferred if scanning).
	go func() {
		time.Sleep(5 * time.Second)
		_ = r.ReportAndCheckAgentUpdate(true)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tickAgentUpdateSchedule()
		}
	}
}

func (r *Runner) tickAgentUpdateSchedule() {
	if r.API == nil || r.Settings == nil {
		return
	}
	if !r.Settings.GetBool(keyApproved) {
		return
	}
	r.ensureAutoScheduleDefaults()
	mins := settings.NormalizeAgentUpdateMinutes(
		r.Settings.Get(settings.KeyAgentUpdateSchedule, ""),
		settings.DefaultAgentUpdateIntervalMinutes,
	)
	last := r.Settings.Get(settings.KeyLastAgentUpdateCheck, "")
	now := time.Now()
	if !settings.IntervalDue(last, mins, now) {
		return
	}
	if r.scanningNow() {
		_ = r.History.Append("update.defer", "Agent update check deferred until scan finishes", nil)
		return
	}
	r.Settings.Set(settings.KeyLastAgentUpdateCheck, settings.FormatIntervalRunStamp(now))
	_ = r.Settings.Save()
	_ = r.ReportAndCheckAgentUpdate(true)
}

// ReportAndCheckAgentUpdate reports the running version and checks Center for a target.
// If autoInstall is true and an update is available, download + stage + hand off to watchdog.
func (r *Runner) ReportAndCheckAgentUpdate(autoInstall bool) error {
	if r.API == nil || r.Settings == nil {
		return fmt.Errorf("not connected")
	}
	current := version.AgentVersion
	r.Settings.Set(settings.KeyAgentVersionCurrent, current)
	schedule := strconv.Itoa(settings.NormalizeAgentUpdateMinutes(
		r.Settings.Get(settings.KeyAgentUpdateSchedule, ""),
		settings.DefaultAgentUpdateIntervalMinutes,
	))
	_, _, _ = r.API.ReportAgentVersion(current, schedule)

	// Always allow version reporting; only block download/install while scanning.
	if autoInstall && r.scanningNow() {
		r.setAgentUpdateStatus("deferred", "Update deferred until scan finishes")
		_, _, _ = r.API.ReportAgentUpdateStatus("deferred", "Update deferred until scan finishes", current, "")
		_ = r.History.Append("update.defer", "Agent update download deferred until scan finishes", nil)
		return nil
	}

	r.setAgentUpdateStatus("checking", "")
	_, _, _ = r.API.ReportAgentUpdateStatus("checking", "Checking for agent update", current, "")

	resp, raw, err := r.API.CheckAgentUpdate(current)
	if err != nil {
		r.setAgentUpdateStatus("failed", err.Error())
		_, _, _ = r.API.ReportAgentUpdateStatus("failed", err.Error(), current, "")
		return err
	}
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("checkAgentUpdate status %d", resp.StatusCode)
		r.setAgentUpdateStatus("failed", msg)
		return fmt.Errorf("%s body=%s", msg, compact(raw))
	}

	var check api.AgentUpdateCheck
	if err := json.Unmarshal(resp.Data, &check); err != nil {
		// Center may return update_available as 0/1 int.
		var loose struct {
			UpdateAvailable any    `json:"update_available"`
			CurrentVersion  string `json:"current_version"`
			TargetVersion   string `json:"target_version"`
			Package         *struct {
				ID        int64  `json:"id"`
				Version   string `json:"version"`
				FileName  string `json:"file_name"`
				Path      string `json:"path"`
				SHA256    string `json:"sha256"`
				SizeBytes int64  `json:"size_bytes"`
				Kind      string `json:"kind"`
			} `json:"package"`
		}
		if err2 := json.Unmarshal(resp.Data, &loose); err2 != nil {
			return err
		}
		check.CurrentVersion = loose.CurrentVersion
		check.TargetVersion = loose.TargetVersion
		check.Package = loose.Package
		switch v := loose.UpdateAvailable.(type) {
		case bool:
			check.UpdateAvailable = v
		case float64:
			check.UpdateAvailable = int(v) != 0
		case string:
			check.UpdateAvailable = v == "1" || strings.EqualFold(v, "true")
		}
	}

	r.Settings.Set(settings.KeyAgentVersionTarget, check.TargetVersion)
	r.Settings.Set(settings.KeyAgentUpdateLastCheck, time.Now().Format(time.RFC3339))
	_ = r.Settings.Save()

	if !check.UpdateAvailable || check.Package == nil || strings.TrimSpace(check.Package.Path) == "" {
		r.setAgentUpdateStatus("up_to_date", "Already on assigned version")
		_, _, _ = r.API.ReportAgentUpdateStatus("up_to_date", "Already on assigned version", current, check.TargetVersion)
		return nil
	}

	r.setAgentUpdateStatus("available", "Update available: "+check.TargetVersion)
	_, _, _ = r.API.ReportAgentUpdateStatus("available", "Update available: "+check.TargetVersion, current, check.TargetVersion)
	if r.History != nil {
		_ = r.History.Append("ui.notify",
			fmt.Sprintf("A new agent version (%s) is available from Center.", check.TargetVersion),
			map[string]any{"kind": "agent_update"})
	}
	if !autoInstall {
		return nil
	}
	return r.DownloadAndStageAgentUpdate(check.TargetVersion, check.Package.ID, check.Package.Path, check.Package.SHA256, check.Package.Kind)
}

// DownloadAndStageAgentUpdate downloads the assigned package, verifies sha256, and asks watchdog to apply.
func (r *Runner) DownloadAndStageAgentUpdate(targetVersion string, packageID int64, relPath, expectedSHA, kind string) error {
	if r.API == nil || r.Settings == nil {
		return fmt.Errorf("not connected")
	}
	current := version.AgentVersion
	if r.scanningNow() {
		r.setAgentUpdateStatus("deferred", "Update deferred until scan finishes")
		_, _, _ = r.API.ReportAgentUpdateStatus("deferred", "Update deferred until scan finishes", current, targetVersion)
		_ = r.History.Append("update.defer", "Agent update download deferred until scan finishes", nil)
		_ = r.History.Append("ui.notify",
			"Agent update will start after the current scan finishes.",
			map[string]any{"kind": "agent_update_deferred"})
		return fmt.Errorf("scan in progress — agent update deferred")
	}
	if kind == "" {
		kind = "agent_binary"
	}
	if strings.TrimSpace(relPath) == "" {
		resp, raw, err := r.API.DownloadAgentPackageMeta(targetVersion, packageID)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("downloadAgentPackage status %d body=%s", resp.StatusCode, compact(raw))
		}
		var meta struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Kind   string `json:"kind"`
		}
		if err := json.Unmarshal(resp.Data, &meta); err != nil {
			return err
		}
		relPath = meta.Path
		if expectedSHA == "" {
			expectedSHA = meta.SHA256
		}
		if meta.Kind != "" {
			kind = meta.Kind
		}
	}

	r.setAgentUpdateStatus("downloading", "Downloading "+targetVersion)
	_, _, _ = r.API.ReportAgentUpdateStatus("downloading", "Downloading agent package", current, targetVersion)

	updateDir := filepath.Join(config.DataBaseDir(), "Data", "updates")
	_ = os.MkdirAll(updateDir, 0o700)
	staged := filepath.Join(updateDir, "insite-agent-"+sanitizeVersion(targetVersion)+".exe")

	gotSHA, err := r.API.DownloadProtectedFileMeta(kind, relPath, staged)
	if err != nil {
		r.setAgentUpdateStatus("failed", err.Error())
		_, _, _ = r.API.ReportAgentUpdateStatus("failed", err.Error(), current, targetVersion)
		_ = r.History.Append("ui.notify",
			"Agent update download failed. Please try again from Settings.",
			map[string]any{"kind": "agent_update_failed"})
		return err
	}
	fileSHA, err := fileSHA256(staged)
	if err != nil {
		return err
	}
	if expectedSHA != "" && !strings.EqualFold(expectedSHA, fileSHA) {
		_ = os.Remove(staged)
		msg := fmt.Sprintf("sha256 mismatch expected=%s got=%s", expectedSHA, fileSHA)
		r.setAgentUpdateStatus("failed", msg)
		_, _, _ = r.API.ReportAgentUpdateStatus("failed", msg, current, targetVersion)
		return fmt.Errorf("%s", msg)
	}
	if gotSHA != "" && !strings.EqualFold(gotSHA, fileSHA) {
		_ = os.Remove(staged)
		msg := "downloaded content sha256 mismatch"
		r.setAgentUpdateStatus("failed", msg)
		return fmt.Errorf("%s", msg)
	}

	r.Settings.Set(settings.KeyAgentUpdateStagedPath, staged)
	r.Settings.Set(settings.KeyAgentUpdateStagedSHA, fileSHA)
	r.Settings.Set(settings.KeyAgentUpdatePending, "true")
	r.Settings.Set(settings.KeyAgentVersionTarget, targetVersion)
	_ = r.Settings.Save()

	pending := pendingUpdatePayload{
		StagedPath:     staged,
		SHA256:         fileSHA,
		TargetVersion:  targetVersion,
		CurrentVersion: current,
		RequestedAt:    time.Now().Format(time.RFC3339),
	}
	pendingPath := filepath.Join(updateDir, PendingUpdateFile)
	b, _ := json.MarshalIndent(pending, "", "  ")
	if err := os.WriteFile(pendingPath, b, 0o600); err != nil {
		return err
	}

	r.setAgentUpdateStatus("ready", "Staged "+targetVersion+"; waiting for watchdog install")
	_, _, _ = r.API.ReportAgentUpdateStatus("ready", "Package staged for watchdog install", current, targetVersion)
	_, _, _ = r.API.ReportAgentUpdateStatus("installing", "Handed off to watchdog", current, targetVersion)
	r.setAgentUpdateStatus("installing", "Watchdog applying update…")
	if r.History != nil {
		_ = r.History.Append("ui.notify",
			fmt.Sprintf("Agent update %s is ready and will be installed shortly.", targetVersion),
			map[string]any{"kind": "agent_update_install"})
	}
	return nil
}

func (r *Runner) setAgentUpdateStatus(status, msg string) {
	if r.Settings == nil {
		return
	}
	r.Settings.Set(settings.KeyAgentUpdateStatus, status)
	if msg != "" {
		r.Settings.Set(settings.KeyTIDownloadMessage, msg) // reuse transient message channel for UI if needed
	}
	_ = r.Settings.Save()
	_ = r.History.Append("agent.update", status+": "+msg, map[string]any{
		"status":  status,
		"message": msg,
	})
}

func sanitizeVersion(v string) string {
	v = strings.TrimSpace(v)
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return repl.Replace(v)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
