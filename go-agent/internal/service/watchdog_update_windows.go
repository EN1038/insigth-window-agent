//go:build windows

package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/install"
	"github.com/sosecure/insite-agent/internal/settings"
)

const pendingUpdateFileName = "pending_update.json"

type pendingUpdateFile struct {
	StagedPath     string `json:"staged_path"`
	SHA256         string `json:"sha256"`
	TargetVersion  string `json:"target_version"`
	CurrentVersion string `json:"current_version"`
	RequestedAt    string `json:"requested_at"`
}

var (
	updateMu   sync.Mutex
	updateBusy bool
)

func pendingUpdatePath() string {
	return filepath.Join(config.DataBaseDir(), "Data", "updates", pendingUpdateFileName)
}

func pendingUpdateInProgress() bool {
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateBusy
}

func tryApplyPendingUpdate() {
	updateMu.Lock()
	if updateBusy {
		updateMu.Unlock()
		return
	}
	path := pendingUpdatePath()
	b, err := os.ReadFile(path)
	if err != nil {
		updateMu.Unlock()
		return
	}
	updateBusy = true
	updateMu.Unlock()
	defer func() {
		updateMu.Lock()
		updateBusy = false
		updateMu.Unlock()
	}()

	var pending pendingUpdateFile
	if err := json.Unmarshal(b, &pending); err != nil {
		_ = os.Remove(path)
		return
	}
	if strings.TrimSpace(pending.StagedPath) == "" {
		_ = os.Remove(path)
		return
	}
	if _, err := os.Stat(pending.StagedPath); err != nil {
		_ = os.Remove(path)
		writeUpdateResult("failed", "staged package missing", pending)
		return
	}
	if pending.SHA256 != "" {
		got, err := hashFileSHA256(pending.StagedPath)
		if err != nil || !strings.EqualFold(got, pending.SHA256) {
			_ = os.Remove(path)
			writeUpdateResult("failed", "staged sha256 mismatch", pending)
			return
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		writeUpdateResult("failed", "cannot resolve install path", pending)
		return
	}
	exePath, _ = filepath.Abs(exePath)
	installExe := filepath.Join(filepath.Dir(exePath), "insite-agent.exe")
	if config.InstallDir() != "" {
		cand := filepath.Join(config.InstallDir(), "insite-agent.exe")
		if _, err := os.Stat(cand); err == nil {
			installExe = cand
		}
	}

	backup := installExe + ".bak"
	_ = os.Remove(backup)

	// Authorize temporary stop so watchdog restart loop does not fight us.
	SetAuthorizedServiceStop(true)
	_ = stopServiceByName(install.ServiceName)
	time.Sleep(2 * time.Second)

	// Backup current, then replace.
	_ = copyFile(installExe, backup)
	if err := copyFile(pending.StagedPath, installExe); err != nil {
		_ = copyFile(backup, installExe)
		_ = startServiceByName(install.ServiceName)
		clearAuthorizedServiceStop()
		_ = os.Remove(path)
		writeUpdateResult("failed", "replace failed: "+err.Error(), pending)
		return
	}

	if err := startServiceByName(install.ServiceName); err != nil {
		_ = copyFile(backup, installExe)
		_ = startServiceByName(install.ServiceName)
		clearAuthorizedServiceStop()
		_ = os.Remove(path)
		writeUpdateResult("rollback", "service start failed; restored previous", pending)
		return
	}

	// Health-check: service should stay running briefly.
	ok := false
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		running, err := isServiceRunning(install.ServiceName)
		if err == nil && running {
			ok = true
			break
		}
	}
	if !ok {
		_ = stopServiceByName(install.ServiceName)
		_ = copyFile(backup, installExe)
		_ = startServiceByName(install.ServiceName)
		clearAuthorizedServiceStop()
		_ = os.Remove(path)
		writeUpdateResult("rollback", "health-check failed; restored previous", pending)
		return
	}

	clearAuthorizedServiceStop()
	_ = os.Remove(path)
	_ = os.Remove(pending.StagedPath)
	writeUpdateResult("success", "installed "+pending.TargetVersion, pending)

	st := settings.New(config.DataBaseDir())
	_ = st.Load()
	st.Set(settings.KeyAgentVersionCurrent, pending.TargetVersion)
	st.Set(settings.KeyAgentUpdateStatus, "success")
	st.Set(settings.KeyAgentUpdatePending, "false")
	_ = st.Save()
}

func writeUpdateResult(status, message string, pending pendingUpdateFile) {
	dir := filepath.Join(config.DataBaseDir(), "Data", "updates")
	_ = os.MkdirAll(dir, 0o700)
	payload := map[string]string{
		"status":          status,
		"message":         message,
		"target_version":  pending.TargetVersion,
		"current_version": pending.CurrentVersion,
		"finished_at":     time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "last_update_result.json"), b, 0o600)

	st := settings.New(config.DataBaseDir())
	_ = st.Load()
	st.Set(settings.KeyAgentUpdateStatus, status)
	if status == "success" && pending.TargetVersion != "" {
		st.Set(settings.KeyAgentVersionCurrent, pending.TargetVersion)
	}
	_ = st.Save()
}

func hashFileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".part"
	if err := os.WriteFile(tmp, in, 0o755); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}
