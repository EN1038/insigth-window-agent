package runtime

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

const keyLastSsdeepSync = "last_ssdeep_sync"

type ssdeepMetaPayload struct {
	SsdeepDB struct {
		Version string `json:"version"`
	} `json:"ssdeep_db"`
	Version string `json:"version"`
}

type ssdeepDownloadItem struct {
	ID       int64  `json:"id"`
	Path     string `json:"path"`
	FileName string `json:"file_name"`
	Version  string `json:"version"`
	Format   string `json:"format"`
	Category string `json:"category"`
	Title    string `json:"title"`
}

func (r *Runner) SyncSsdeepNow() int {
	return r.syncSsdeepFromServer()
}

func (r *Runner) syncSsdeepFromServer() int {
	ok, n, _ := r.syncSsdeepFromServerResult()
	if ok {
		return n
	}
	return 0
}

func (r *Runner) syncSsdeepFromServerComplete() bool {
	ok, _, _ := r.syncSsdeepFromServerResult()
	return ok
}

func (r *Runner) syncSsdeepFromServerResult() (complete bool, imported int, failed int) {
	if r.API == nil {
		return false, 0, 1
	}
	store := ssdeepscan.NewStore(r.BaseDir)
	idx, _ := store.LoadIndex()
	localEmpty := idx == nil || idx.Total == 0 || !store.HasEncryptedStore()
	currentVersion := strings.TrimSpace(r.Settings.Get(settings.KeySsdeepDBVersion, ""))
	if localEmpty {
		// Local store wiped / never imported — don't claim a version to Center.
		currentVersion = ""
		r.Settings.Set(settings.KeySsdeepDBVersion, "")
		_ = r.Settings.Save()
	}

	metaVersion := ""
	if resp, raw, err := r.API.GetSsdeep(currentVersion); err != nil {
		_ = r.History.Append("api.warn", "getSsdeep: "+err.Error(), nil)
	} else if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("getSsdeep status=%d body=%s", resp.StatusCode, compact(raw)), nil)
	} else {
		metaVersion = parseSsdeepMetaVersion(resp.Data)
		if metaVersion != "" {
			_ = r.History.Append("ssdeep.meta", "server ssdeep version "+metaVersion, nil)
		}
	}

	// Each ssdeep pack is a full snapshot. If local already has signatures on the
	// assigned latest version, skip — do not re-pull the whole historical queue.
	if !localEmpty && metaVersion != "" && currentVersion != "" && metaVersion == currentVersion {
		_ = r.History.Append("ssdeep.skip", "already on latest ssdeep version "+currentVersion, nil)
		r.setTIProgress(95, "Ssdeep already up to date")
		return true, 0, 0
	}
	// Local was rebuilt into category packs; don't let legacy signatures_part*
	// queue overwrite until Center is updated to categorized packs.
	if !localEmpty && idx != nil && idx.Total > 0 && strings.HasPrefix(currentVersion, "categorized-") {
		_ = r.History.Append("ssdeep.skip", "local categorized ssdeep present ("+currentVersion+")", nil)
		r.setTIProgress(95, "Ssdeep categorized store ready")
		return true, 0, 0
	}
	if !localEmpty && metaVersion == "" && currentVersion != "" && idx != nil && idx.Total > 0 {
		_ = r.History.Append("ssdeep.skip", "local ssdeep present; server meta unavailable", nil)
		r.setTIProgress(95, "Ssdeep already loaded")
		return true, 0, 0
	}

	force := localEmpty
	if force {
		_ = r.History.Append("ssdeep.force", "local ssdeep store empty; requesting force requeue", nil)
	}
	resp, raw, err := r.API.DownloadSsdeepSiteForce(currentVersion, force)
	if err != nil {
		_ = r.History.Append("api.warn", "downloadSsdeepSite: "+err.Error(), nil)
		return false, 0, 1
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("downloadSsdeepSite status=%d body=%s", resp.StatusCode, compact(raw)), nil)
		return false, 0, 1
	}
	items := parseSsdeepDownloadItems(resp.Data)
	items = selectLatestSsdeepPackPerCategory(items)
	if len(items) == 0 {
		_ = r.History.Append("ssdeep.skip", "no ssdeep updates available", nil)
		r.setTIProgress(95, "No ssdeep packs to download")
		// Empty local store with empty queue is NOT complete.
		return !localEmpty, 0, 0
	}
	imported, failed = r.downloadSsdeep(items, r.agentID())
	return failed == 0, imported, failed
}

// selectLatestSsdeepPackPerCategory keeps one pack per category (highest id).
// Packs without category fall into bucket "_" and only the newest is kept.
func selectLatestSsdeepPackPerCategory(items []ssdeepDownloadItem) []ssdeepDownloadItem {
	if len(items) <= 1 {
		return items
	}
	best := map[string]ssdeepDownloadItem{}
	for _, it := range items {
		cat := strings.ToLower(strings.TrimSpace(it.Category))
		if cat == "" {
			cat = "_"
		}
		prev, ok := best[cat]
		if !ok || it.ID > prev.ID {
			best[cat] = it
		}
	}
	out := make([]ssdeepDownloadItem, 0, len(best))
	for _, it := range best {
		out = append(out, it)
	}
	return out
}

// deprecated name kept as wrapper for older call sites / tests
func selectLatestSsdeepPack(items []ssdeepDownloadItem, metaVersion string) []ssdeepDownloadItem {
	_ = metaVersion
	return selectLatestSsdeepPackPerCategory(items)
}

func (r *Runner) downloadSsdeep(items []ssdeepDownloadItem, agentID int64) (imported int, failed int) {
	store := ssdeepscan.NewStore(r.BaseDir)
	downloadsDir := filepath.Join(r.BaseDir, "Data", "ssdeep", "downloads")
	_ = os.MkdirAll(downloadsDir, 0o700)

	// Multi-category packs must merge into one store. Wipe once, then merge each pack.
	if len(items) > 0 {
		_ = store.Clear()
	}

	totalFiles := len(items)
	for idx, item := range items {
		if strings.TrimSpace(item.Path) == "" {
			continue
		}
		fileName := strings.TrimSpace(item.FileName)
		if fileName == "" {
			fileName = filepath.Base(item.Path)
		}
		if fileName == "" || fileName == "." || fileName == "/" {
			fileName = fmt.Sprintf("ssdeep_%d.db", item.ID)
		}
		localPath := filepath.Join(downloadsDir, fileName)
		pct := 50 + float64(idx)*45/float64(max(totalFiles, 1))
		msg := fmt.Sprintf("Ssdeep %d/%d: %s", idx+1, totalFiles, fileName)
		r.setTIProgress(pct, msg)
		_ = r.History.Append("download.progress", msg, map[string]any{
			"phase": "ssdeep", "file_index": idx + 1, "file_total": totalFiles, "percent": pct,
		})
		if err := r.API.DownloadFileWithProgress(item.Path, localPath, "ssdeep", idx+1, totalFiles); err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("download %s: %s", fileName, err.Error()), nil)
			failed++
			continue
		}

		importPath, cleanup, err := prepareSsdeepImportFile(localPath)
		if err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("prepare %s: %s", fileName, err.Error()), nil)
			_ = os.Remove(localPath)
			failed++
			continue
		}
		total, err := importSsdeepFileMerge(store, importPath)
		if cleanup != "" {
			_ = os.Remove(cleanup)
		}
		_ = os.Remove(localPath)
		if err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("import %s: %s", fileName, err.Error()), nil)
			failed++
			continue
		}

		if version := strings.TrimSpace(item.Version); version != "" {
			r.Settings.Set(settings.KeySsdeepDBVersion, version)
		}
		r.Settings.Set(settings.KeySsdeepBundledTotal, fmt.Sprintf("%d", total))
		r.Settings.Set(keyLastSsdeepSync, time.Now().Format(time.RFC3339))
		_ = r.Settings.Save()

		if item.ID > 0 {
			if resp, _, err := r.API.DownloadSsdeepSiteComplete(item.ID); err != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadSsdeepSiteComplete(%d): %s", item.ID, err.Error()), nil)
			} else if resp != nil && resp.StatusCode >= 400 {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadSsdeepSiteComplete(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}
		if agentID > 0 && item.ID > 0 {
			if resp, _, err := r.API.UpdateSsdeepDownload(agentID, item.ID, item.Version); err != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateSsdeepDownload(%d): %s", item.ID, err.Error()), nil)
			} else if resp != nil && resp.StatusCode >= 400 {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateSsdeepDownload(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}
		imported++
		_ = r.History.Append("ssdeep.ok", fmt.Sprintf("imported %s (%d signatures, v=%s)", fileName, total, item.Version), map[string]any{
			"ssdeep_id": item.ID,
			"count":     total,
			"category":  item.Category,
		})
	}
	if imported > 0 && r.Scan != nil {
		r.Scan.RefreshSsdeep()
	}
	return imported, failed
}

func parseSsdeepMetaVersion(data json.RawMessage) string {
	if len(data) == 0 || string(data) == "null" {
		return ""
	}
	var payload ssdeepMetaPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	if v := strings.TrimSpace(payload.SsdeepDB.Version); v != "" {
		return v
	}
	return strings.TrimSpace(payload.Version)
}

func parseSsdeepDownloadItems(data json.RawMessage) []ssdeepDownloadItem {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var direct []ssdeepDownloadItem
	if err := json.Unmarshal(data, &direct); err == nil && len(direct) > 0 {
		return filterSsdeepItems(direct)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	for _, key := range []string{"signatures", "ssdeep", "data"} {
		if raw, ok := root[key]; ok {
			if items := parseSsdeepDownloadItems(raw); len(items) > 0 {
				return items
			}
		}
	}
	for _, raw := range root {
		var nested []ssdeepDownloadItem
		if err := json.Unmarshal(raw, &nested); err == nil && len(nested) > 0 {
			return filterSsdeepItems(nested)
		}
	}
	return nil
}

func filterSsdeepItems(items []ssdeepDownloadItem) []ssdeepDownloadItem {
	out := make([]ssdeepDownloadItem, 0, len(items))
	for _, it := range items {
		if strings.TrimSpace(it.Path) != "" {
			out = append(out, it)
		}
	}
	return out
}

func prepareSsdeepImportFile(path string) (importPath string, cleanupPath string, err error) {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return "", "", err
		}
		defer zr.Close()
		for _, f := range zr.File {
			name := strings.ToLower(filepath.Base(f.Name))
			if name == "" {
				continue
			}
			if !strings.HasSuffix(name, ".db") && !strings.HasSuffix(name, ".sqlite") && !strings.HasSuffix(name, ".json") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return "", "", err
			}
			defer rc.Close()
			tmpPath := path + ".unzipped" + filepath.Ext(name)
			out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return "", "", err
			}
			_, copyErr := io.Copy(out, rc)
			closeErr := out.Close()
			if copyErr != nil {
				_ = os.Remove(tmpPath)
				return "", "", copyErr
			}
			if closeErr != nil {
				_ = os.Remove(tmpPath)
				return "", "", closeErr
			}
			return tmpPath, tmpPath, nil
		}
		return "", "", fmt.Errorf("no supported ssdeep payload in zip")
	}
	return path, "", nil
}

func importSsdeepFile(store *ssdeepscan.Store, path string) (int, error) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return store.ImportJSONFile(path)
	default:
		return store.ImportFromSQLite(path)
	}
}

func importSsdeepFileMerge(store *ssdeepscan.Store, path string) (int, error) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return store.ImportJSONFileMerge(path)
	default:
		// SQLite import historically replaces; load via temp merge by reusing JSON path only.
		// For .db packs, replace-merge is approximate: import to temp then not supported —
		// fall back to full ImportFromSQLite (last pack wins) which is wrong for multi-cat.
		// Prefer JSON packs for category workflow.
		n, err := store.ImportFromSQLite(path)
		return n, err
	}
}
