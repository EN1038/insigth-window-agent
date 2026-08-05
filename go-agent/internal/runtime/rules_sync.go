package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/securefs"
	"github.com/sosecure/insite-agent/internal/settings"
)

type ruleDownloadItem struct {
	ID       int64  `json:"id"`
	Path     string `json:"path"`
	FileName string `json:"file_name"`
	RuleName string `json:"rule_name"`
}

type ruleCatalogItem struct {
	Status      string `json:"status"`
	FileName    string `json:"file_name"`
	RuleName    string `json:"rule_name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
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
	beforeBatch := r.Settings.Get(settings.KeyBatchJobEveryDay, "")
	beforeTI := r.Settings.Get(settings.KeyTISyncEveryDay, "")
	beforeUpd := r.Settings.Get(settings.KeyAgentUpdateSchedule, "")
	if err := applyGetConfig(r.Settings, resp.Data); err != nil {
		_ = r.History.Append("config.error", "apply getConfig: "+err.Error(), nil)
		return err
	}
	_ = r.History.Append("config.ok", "getConfig applied", nil)
	afterBatch := r.Settings.Get(settings.KeyBatchJobEveryDay, "")
	afterTI := r.Settings.Get(settings.KeyTISyncEveryDay, "")
	afterUpd := r.Settings.Get(settings.KeyAgentUpdateSchedule, "")
	if beforeBatch != afterBatch || beforeTI != afterTI || beforeUpd != afterUpd {
		_ = r.History.Append("ui.notify", "Settings updated from Center", map[string]any{"kind": "config"})
	}
	return nil
}

func (r *Runner) SyncRulesNow() int {
	_, n, _ := r.syncRulesFromServerResult(nil)
	return n
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
	rStore := rules.New(r.BaseDir)
	localCount := rStore.FileCount()

	respGetRule, _, errGetRule := r.API.GetRule()
	serverRuleNames := 0
	serverFileCount := 0
	serverPacks := 0
	var catalog []ruleCatalogItem
	if errGetRule == nil && respGetRule != nil && respGetRule.StatusCode == 200 {
		catalog, serverRuleNames, serverFileCount, serverPacks = parseRuleCatalogWithCounts(respGetRule.Data)
		if serverFileCount == 0 && len(catalog) > 0 {
			catalog = uniqueCatalogByFile(catalog)
			serverFileCount = len(catalog)
		}
		if serverRuleNames == 0 {
			serverRuleNames = len(catalog)
		}
	} else if errGetRule != nil {
		_ = r.History.Append("api.warn", "getRule: "+errGetRule.Error(), nil)
	} else if respGetRule != nil {
		_ = r.History.Append("api.warn", fmt.Sprintf("getRule status=%d", respGetRule.StatusCode), nil)
	}

	prevServer := atoiDefault(r.Settings.Get(settings.KeyServerRuleFilesCount, ""), 0)
	if prevServer == 0 {
		prevServer = atoiDefault(r.Settings.Get(settings.KeyServerRulesCount, "0"), 0)
	}
	prevLocal := atoiDefault(r.Settings.Get(settings.KeyLocalRulesCount, "0"), localCount)
	r.recordRulesCountDelta(serverRuleNames, serverFileCount, localCount, prevServer, prevLocal)

	// Force when clearly behind catalog, or when Center has packs but local store is still tiny/bundled-only.
	force := (serverFileCount > 0 && localCount < serverFileCount) ||
		(serverPacks > 0 && localCount < 20) ||
		(serverRuleNames > 0 && localCount < serverRuleNames && localCount < 20)
	if force {
		if respReset, _, errReset := r.API.ResetRuleDownload(); errReset != nil {
			_ = r.History.Append("api.warn", "resetRuleDownload: "+errReset.Error(), nil)
		} else if respReset == nil {
			_ = r.History.Append("api.warn", "resetRuleDownload: empty response", nil)
		} else if respReset.StatusCode != 200 && respReset.StatusCode != 0 {
			// status_code=0 often means encrypted envelope without inner code; treat only non-zero fails as real.
			_ = r.History.Append("api.warn", fmt.Sprintf("resetRuleDownload status=%d error=%s", respReset.StatusCode, respReset.Error), nil)
		} else {
			if respReset.StatusCode == 0 {
				respReset.StatusCode = 200
			}
			_ = r.History.Append("rules.sync", fmt.Sprintf(
				"requested Center re-queue (local=%d server_files=%d)", localCount, serverFileCount), nil)
		}
	}

	resp, raw, err := r.API.DownloadRuleSiteForce(force)
	useOfficial := false
	var items []ruleDownloadItem
	listOK := false

	if err == nil && resp.StatusCode == 200 {
		items = parseRuleDownloadItems(resp.Data)
		useOfficial = len(items) > 0
		listOK = true
	}

	// When pack queue is empty after force, report clear status. Content only
	// comes from downloadRuleSite ZIP/rule_files packs.
	if len(items) == 0 && serverFileCount > 0 {
		if localCount < serverFileCount {
			msg := fmt.Sprintf(
				"YARA behind server: names=%d files=%d local=%d (missing≈%d) — no packs queued (assign/re-queue packs on Center)",
				serverRuleNames, serverFileCount, localCount, serverFileCount-localCount)
			_ = r.History.Append("rules.warn", msg, map[string]any{
				"server_names": serverRuleNames,
				"server_files": serverFileCount,
				"local":        localCount,
				"force":        force,
			})
			r.setTIProgress(45, msg)
			return false, 0, 1
		}
		if localCount == serverFileCount {
			_ = r.History.Append("rules.skip", fmt.Sprintf(
				"YARA file counts match (server_files=%d local=%d rule_names=%d) — nothing to download",
				serverFileCount, localCount, serverRuleNames), nil)
			r.setTIProgress(45, fmt.Sprintf("YARA rules ready (%d files / %d names)", localCount, serverRuleNames))
			return true, 0, 0
		}
		_ = r.History.Append("rules.skip", fmt.Sprintf(
			"local YARA files (%d) > server files (%d) — keeping local store", localCount, serverFileCount), nil)
		r.setTIProgress(45, fmt.Sprintf("YARA rules ready (local=%d server_files=%d)", localCount, serverFileCount))
		return true, 0, 0
	}

	if len(items) == 0 {
		items = parseRuleDownloadItems(fallbackRaw)
		useOfficial = false
		if len(items) == 0 {
			if localCount > 0 {
				_ = r.History.Append("rules.skip", fmt.Sprintf(
					"no new YARA packs from Center; continuing with local store (%d files)", localCount), nil)
				r.setTIProgress(45, fmt.Sprintf("YARA rules ready (%d files)", localCount))
				return true, 0, 0
			}
			// Empty local store must NOT count as complete — otherwise bootstrap
			// finishes and scans fail with "no rules in store".
			_ = r.History.Append("rules.warn", "no YARA packs available and local store empty — will retry", nil)
			r.setTIProgress(45, "Waiting for YARA packs from Center…")
			if err != nil {
				_ = r.History.Append("api.warn", "downloadRuleSite: "+err.Error(), nil)
			} else if resp != nil && !listOK {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadRuleSite status=%d body=%s", resp.StatusCode, compact(raw)), nil)
			}
			return false, 0, 1
		}
		_ = r.History.Append("rules.fallback", "using approval/fallback rules JSON", nil)
		listOK = true
	}

	imported, failed, notFound := r.downloadRules(items, agentID, useOfficial)
	localCount = rStore.FileCount()
	r.persistRulesCounts(serverRuleNames, serverFileCount, localCount)

	hasRules := localCount > 0
	complete = (failed == 0) || (imported > 0) || hasRules
	if serverFileCount > 0 && localCount < serverFileCount && failed > 0 {
		// Missing files on Center (404) will never succeed — don't trap the UI on the
		// bootstrap screen forever when a usable local rule store already exists.
		if notFound >= failed && hasRules {
			_ = r.History.Append("rules.warn", fmt.Sprintf(
				"Center pack(s) missing on disk (%d) — continuing with local=%d (server_files=%d)",
				notFound, localCount, serverFileCount), nil)
			r.setTIProgress(50, fmt.Sprintf("YARA: local %d ready (Center missing %d pack)", localCount, notFound))
			complete = true
		} else {
			complete = false
		}
	}
	return complete, imported, failed
}

func (r *Runner) recordRulesCountDelta(serverRuleNames, serverFiles, localCount, prevServer, prevLocal int) {
	deltaServer := serverRuleNames - prevServer
	deltaLocal := localCount - prevLocal
	deltaGap := serverFiles - localCount

	serverTrend := "unchanged"
	switch {
	case deltaServer > 0:
		serverTrend = fmt.Sprintf("increased +%d", deltaServer)
	case deltaServer < 0:
		serverTrend = fmt.Sprintf("decreased %d", deltaServer)
	}
	gapTrend := "in sync"
	switch {
	case deltaGap > 0:
		gapTrend = fmt.Sprintf("local behind by %d files", deltaGap)
	case deltaGap < 0:
		gapTrend = fmt.Sprintf("local ahead by %d files", -deltaGap)
	}

	msg := fmt.Sprintf("YARA count check: server_files=%d local_files=%d (Δlocal=%+d) packs_gap=%s — names=%d (%s)",
		serverFiles, localCount, deltaLocal, gapTrend, serverRuleNames, serverTrend)
	_ = r.History.Append("rules.count", msg, map[string]any{
		"server_names": serverRuleNames,
		"server_files": serverFiles,
		"local":        localCount,
		"prev_server":  prevServer,
		"prev_local":   prevLocal,
		"delta_server": deltaServer,
		"delta_local":  deltaLocal,
		"delta_gap":    deltaGap,
	})
	r.persistRulesCounts(serverRuleNames, serverFiles, localCount)
	r.setTIProgress(8, fmt.Sprintf("YARA: %d local / %d server files", localCount, serverFiles))
}

func (r *Runner) persistRulesCounts(serverNames, serverFiles, localCount int) {
	if r.Settings == nil {
		return
	}
	// Keep KeyServerRulesCount as file count for BehindServer / UI (legacy key name).
	if serverFiles > 0 {
		r.Settings.Set(settings.KeyServerRulesCount, strconv.Itoa(serverFiles))
		r.Settings.Set(settings.KeyServerRuleFilesCount, strconv.Itoa(serverFiles))
	} else if serverNames > 0 {
		// Fallback only when unique_files unavailable.
		r.Settings.Set(settings.KeyServerRulesCount, strconv.Itoa(serverNames))
	}
	r.Settings.Set(settings.KeyLocalRulesCount, strconv.Itoa(localCount))
	_ = r.Settings.Save()
}

func (r *Runner) downloadRules(items []ruleDownloadItem, agentID int64, useOfficialComplete bool) (imported int, failed int, notFound int) {
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
		localPath := filepath.Join(paths, fileName)

		pct := 5 + float64(idx)*40/float64(max(total, 1))
		msg := fmt.Sprintf("YARA rules %d/%d: %s", idx+1, total, fileName)
		r.setTIProgress(pct, msg)
		_ = r.History.Append("download.progress", msg, map[string]any{
			"phase": "rules", "file_index": idx + 1, "file_total": total, "percent": pct,
		})

		if err := r.API.DownloadFileWithProgress(item.Path, localPath, "rules", idx+1, total); err != nil {
			errMsg := err.Error()
			_ = r.History.Append("rules.warn", fmt.Sprintf("download static rule %s: %s", fileName, errMsg), nil)
			failed++
			if isMissingRemotePack(errMsg) {
				notFound++
			}
			continue
		}

		ext := strings.ToLower(filepath.Ext(localPath))
		var version string
		var ruleCount int
		var err error
		switch ext {
		case ".zip":
			version, ruleCount, err = store.ImportZip(localPath, ruleName)
		case ".yar", ".yara":
			rel := item.FileName
			if rel == "" {
				rel = item.Path
			}
			data, readErr := os.ReadFile(localPath)
			if readErr != nil {
				err = readErr
				break
			}
			err = store.PutIndexed(ruleName, rel, data)
			if err == nil {
				ruleCount = 1
				version = r.Settings.Get(settings.KeyRulesVersion, "catalog")
			}
		default:
			// Try zip first; if that fails treat as plaintext yar.
			version, ruleCount, err = store.ImportZip(localPath, ruleName)
			if err != nil {
				data, readErr := os.ReadFile(localPath)
				if readErr != nil {
					err = fmt.Errorf("unsupported rule payload %s: %v / %v", fileName, err, readErr)
					break
				}
				rel := item.FileName
				if rel == "" {
					rel = item.Path
				}
				err = store.PutIndexed(ruleName, rel, data)
				if err == nil {
					ruleCount = 1
					version = r.Settings.Get(settings.KeyRulesVersion, "catalog")
				}
			}
		}
		if err != nil {
			_ = r.History.Append("rules.error", fmt.Sprintf("import %s: %s", fileName, err.Error()), nil)
			_ = securefs.WipeAndRemove(localPath)
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

		_ = securefs.WipeAndRemove(localPath)
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
	return imported, failed, notFound
}

func isMissingRemotePack(errMsg string) bool {
	s := strings.ToLower(errMsg)
	return strings.Contains(s, "status 404") ||
		strings.Contains(s, "file not found") ||
		strings.Contains(s, "not found")
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

func parseRuleCatalog(data json.RawMessage) []ruleCatalogItem {
	items, _, _, _ := parseRuleCatalogWithCounts(data)
	return items
}

func parseRuleCatalogWithCounts(data json.RawMessage) (items []ruleCatalogItem, ruleNames, uniqueFiles, packs int) {
	if len(data) == 0 || string(data) == "null" {
		return nil, 0, 0, 0
	}
	var direct []ruleCatalogItem
	if err := json.Unmarshal(data, &direct); err == nil && len(direct) > 0 {
		items = filterCatalogItems(direct)
		return items, len(items), len(uniqueCatalogByFile(items)), 0
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, 0, 0, 0
	}
	if countsRaw, ok := root["counts"]; ok {
		var counts struct {
			RuleNames   int `json:"rule_names"`
			UniqueFiles int `json:"unique_files"`
			Packs       int `json:"packs"`
		}
		if json.Unmarshal(countsRaw, &counts) == nil {
			ruleNames = counts.RuleNames
			uniqueFiles = counts.UniqueFiles
			packs = counts.Packs
		}
	}
	for _, key := range []string{"rules", "data", "rule_name"} {
		if raw, ok := root[key]; ok {
			sub, rn, uf, pk := parseRuleCatalogWithCounts(raw)
			if len(sub) > 0 {
				items = sub
			}
			if ruleNames == 0 {
				ruleNames = rn
			}
			if uniqueFiles == 0 {
				uniqueFiles = uf
			}
			if packs == 0 {
				packs = pk
			}
		}
	}
	if len(items) == 0 {
		for _, v := range root {
			var nested []ruleCatalogItem
			if err := json.Unmarshal(v, &nested); err == nil {
				if filtered := filterCatalogItems(nested); len(filtered) > 0 {
					items = filtered
					break
				}
			}
		}
	}
	if ruleNames == 0 && len(items) > 0 {
		ruleNames = len(items)
	}
	if uniqueFiles == 0 && len(items) > 0 {
		uniqueFiles = len(uniqueCatalogByFile(items))
	}
	return items, ruleNames, uniqueFiles, packs
}

func filterCatalogItems(items []ruleCatalogItem) []ruleCatalogItem {
	out := make([]ruleCatalogItem, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.FileName) == "" && strings.TrimSpace(it.RuleName) == "" {
			continue
		}
		out = append(out, it)
	}
	return out
}

func uniqueCatalogByFile(catalog []ruleCatalogItem) []ruleCatalogItem {
	seen := map[string]bool{}
	out := make([]ruleCatalogItem, 0, len(catalog))
	for _, it := range catalog {
		key := strings.ToLower(strings.TrimSpace(it.FileName))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	return out
}

func filterRuleItems(items []ruleDownloadItem) []ruleDownloadItem {
	out := make([]ruleDownloadItem, 0, len(items))
	for _, it := range items {
		if it.Path == "" && it.FileName != "" {
			it.Path = it.FileName
		}
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

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
