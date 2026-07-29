package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/settings"
)

type ruleDownloadItem struct {
	ID       int64  `json:"id"`
	Path     string `json:"path"`
	RuleName string `json:"rule_name"`
}

func (r *Runner) syncConfigFromServer() error {
	resp, raw, err := r.API.GetConfig()
	if err != nil {
		_ = r.History.Append("api.error", "getConfig: "+err.Error(), nil)
		return err
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("getConfig status=%d body=%s", resp.StatusCode, compact(raw)), nil)
		return fmt.Errorf("getConfig status %d", resp.StatusCode)
	}
	if err := applyGetConfig(r.Settings, resp.Data); err != nil {
		_ = r.History.Append("config.error", "apply getConfig: "+err.Error(), nil)
		return err
	}
	_ = r.History.Append("config.ok", "getConfig applied", nil)
	return nil
}

func (r *Runner) syncRulesFromServer(fallbackRaw json.RawMessage) int {
	ok, n, _ := r.syncRulesFromServerResult(fallbackRaw)
	if ok {
		return n
	}
	return 0
}

// syncRulesFromServerComplete returns true when listing succeeded and every file downloaded
// (or there was nothing to download).
func (r *Runner) syncRulesFromServerComplete(fallbackRaw json.RawMessage) bool {
	ok, _, _ := r.syncRulesFromServerResult(fallbackRaw)
	return ok
}

func (r *Runner) syncRulesFromServerResult(fallbackRaw json.RawMessage) (complete bool, imported int, failed int) {
	agentID := r.agentID()

	_, _, _ = r.API.GetRule()

	resp, raw, err := r.API.DownloadRuleSite()
	useOfficial := false
	var items []ruleDownloadItem
	listOK := false

	if err == nil && resp.StatusCode == 200 {
		items = parseRuleDownloadItems(resp.Data)
		useOfficial = len(items) > 0
		listOK = true
	}
	if len(items) == 0 {
		items = parseRuleDownloadItems(fallbackRaw)
		useOfficial = false
		if len(items) == 0 {
			if listOK {
				_ = r.History.Append("rules.skip", "no rules available to sync", nil)
				r.setTIProgress(45, "YARA rules: no packs on server — continuing to ssdeep")
				return true, 0, 0
			}
			if err != nil {
				_ = r.History.Append("api.warn", "downloadRuleSite: "+err.Error(), nil)
			} else if resp != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadRuleSite status=%d body=%s", resp.StatusCode, compact(raw)), nil)
			}
			return false, 0, 1
		}
		_ = r.History.Append("rules.fallback", "using approval/fallback rules JSON", nil)
		listOK = true
	}

	imported, failed = r.downloadRules(items, agentID, useOfficial)
	return failed == 0, imported, failed
}

func (r *Runner) downloadRules(items []ruleDownloadItem, agentID int64, useOfficialComplete bool) (imported int, failed int) {
	store := rules.New(r.BaseDir)
	paths := filepath.Join(r.BaseDir, "Data", "rules", "downloads")
	_ = os.MkdirAll(paths, 0o700)

	total := len(items)
	for idx, item := range items {
		if item.Path == "" {
			continue
		}
		ruleName := item.RuleName
		if ruleName == "" {
			ruleName = "server"
		}
		fileName := filepath.Base(item.Path)
		if fileName == "" || fileName == "." || fileName == "/" {
			fileName = fmt.Sprintf("rule_%d.zip", item.ID)
		}
		localZip := filepath.Join(paths, fileName)

		pct := 5 + float64(idx)*40/float64(max(total, 1))
		msg := fmt.Sprintf("YARA rules %d/%d: %s", idx+1, total, fileName)
		r.setTIProgress(pct, msg)
		_ = r.History.Append("download.progress", msg, map[string]any{
			"phase": "rules", "file_index": idx + 1, "file_total": total, "percent": pct,
		})

		if err := r.API.DownloadFileWithProgress(item.Path, localZip, "rules", idx+1, total); err != nil {
			_ = r.History.Append("rules.error", fmt.Sprintf("download %s: %s", fileName, err.Error()), nil)
			failed++
			continue
		}

		version, ruleCount, err := store.ImportZip(localZip, ruleName)
		if err != nil {
			_ = r.History.Append("rules.error", fmt.Sprintf("import %s: %s", fileName, err.Error()), nil)
			_ = os.Remove(localZip)
			failed++
			continue
		}

		if version != "" {
			v := version
			if len(v) > 16 {
				v = v[:16]
			}
			r.Settings.Set(settings.KeyRulesVersion, v)
			_ = r.Settings.Save()
		}

		if useOfficialComplete && item.ID > 0 {
			if resp, _, err := r.API.DownloadRuleSiteComplete(item.ID); err != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadRuleSiteComplete(%d): %s", item.ID, err.Error()), nil)
			} else if resp.StatusCode != 200 {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadRuleSiteComplete(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}
		if agentID > 0 && item.ID > 0 {
			if resp, _, err := r.API.UpdateRuleDownload(agentID, item.ID); err != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateRuleDownload(%d): %s", item.ID, err.Error()), nil)
			} else if resp.StatusCode != 200 {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateRuleDownload(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}

		_ = os.Remove(localZip)
		imported++
		_ = r.History.Append("rules.ok", fmt.Sprintf("imported %s (%d files, v=%s)", fileName, ruleCount, version), map[string]any{
			"rule_id": item.ID,
			"count":   ruleCount,
		})
	}
	if imported > 0 && r.Scan != nil {
		r.Scan.RefreshRules()
	}
	if total > 0 {
		r.setTIProgress(50, fmt.Sprintf("YARA rules done (%d ok, %d failed)", imported, failed))
	} else {
		r.setTIProgress(50, "YARA rules: nothing to download")
	}
	return imported, failed
}

func parseRuleDownloadItems(data json.RawMessage) []ruleDownloadItem {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	var direct []ruleDownloadItem
	if err := json.Unmarshal(data, &direct); err == nil && len(direct) > 0 {
		return filterRuleItems(direct)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}

	if rulesRaw, ok := root["rules"]; ok {
		if items := parseRuleDownloadItems(rulesRaw); len(items) > 0 {
			return items
		}
	}
	for _, v := range root {
		var nested []ruleDownloadItem
		if err := json.Unmarshal(v, &nested); err == nil {
			if items := filterRuleItems(nested); len(items) > 0 {
				return items
			}
		}
	}
	return nil
}

func filterRuleItems(items []ruleDownloadItem) []ruleDownloadItem {
	out := make([]ruleDownloadItem, 0, len(items))
	for _, it := range items {
		if it.Path != "" {
			out = append(out, it)
		}
	}
	return out
}

func (r *Runner) agentID() int64 {
	s := strings.TrimSpace(r.Settings.Get(keyAgentID, "0"))
	if s == "" || s == "0" {
		return 0
	}
	var id int64
	fmt.Sscanf(s, "%d", &id)
	return id
}
