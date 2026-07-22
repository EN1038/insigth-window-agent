package runtime

import (
	"archive/zip"
	"context"
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
}

func (r *Runner) ssdeepSyncLoop(ctx context.Context) {
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
			if n := r.syncSsdeepFromServer(); n > 0 {
				r.Settings.Set(keyLastSsdeepSync, time.Now().Format(time.RFC3339))
				_ = r.Settings.Save()
			}
		}
	}
}

func (r *Runner) syncSsdeepFromServer() int {
	if r.API == nil {
		return 0
	}
	currentVersion := strings.TrimSpace(r.Settings.Get(settings.KeySsdeepDBVersion, ""))
	if resp, raw, err := r.API.GetSsdeep(currentVersion); err != nil {
		_ = r.History.Append("api.warn", "getSsdeep: "+err.Error(), nil)
	} else if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("getSsdeep status=%d body=%s", resp.StatusCode, compact(raw)), nil)
	} else if metaVersion := parseSsdeepMetaVersion(resp.Data); metaVersion != "" {
		_ = r.History.Append("ssdeep.meta", "server ssdeep version "+metaVersion, nil)
	}

	resp, raw, err := r.API.DownloadSsdeepSite(currentVersion)
	if err != nil {
		_ = r.History.Append("api.warn", "downloadSsdeepSite: "+err.Error(), nil)
		return 0
	}
	if resp.StatusCode != 200 {
		_ = r.History.Append("api.warn", fmt.Sprintf("downloadSsdeepSite status=%d body=%s", resp.StatusCode, compact(raw)), nil)
		return 0
	}
	items := parseSsdeepDownloadItems(resp.Data)
	if len(items) == 0 {
		_ = r.History.Append("ssdeep.skip", "no ssdeep updates available", nil)
		return 0
	}
	return r.downloadSsdeep(items, r.agentID())
}

func (r *Runner) downloadSsdeep(items []ssdeepDownloadItem, agentID int64) int {
	store := ssdeepscan.NewStore(r.BaseDir)
	downloadsDir := filepath.Join(r.BaseDir, "Data", "ssdeep", "downloads")
	_ = os.MkdirAll(downloadsDir, 0o700)

	count := 0
	for _, item := range items {
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
		if err := r.API.DownloadFile(item.Path, localPath); err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("download %s: %s", fileName, err.Error()), nil)
			continue
		}

		importPath, cleanup, err := prepareSsdeepImportFile(localPath)
		if err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("prepare %s: %s", fileName, err.Error()), nil)
			_ = os.Remove(localPath)
			continue
		}
		total, err := importSsdeepFile(store, importPath)
		if cleanup != "" {
			_ = os.Remove(cleanup)
		}
		_ = os.Remove(localPath)
		if err != nil {
			_ = r.History.Append("ssdeep.error", fmt.Sprintf("import %s: %s", fileName, err.Error()), nil)
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
			} else if resp.StatusCode != 200 {
				_ = r.History.Append("api.warn", fmt.Sprintf("downloadSsdeepSiteComplete(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}
		if agentID > 0 && item.ID > 0 {
			if resp, _, err := r.API.UpdateSsdeepDownload(agentID, item.ID, item.Version); err != nil {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateSsdeepDownload(%d): %s", item.ID, err.Error()), nil)
			} else if resp.StatusCode != 200 {
				_ = r.History.Append("api.warn", fmt.Sprintf("updateSsdeepDownload(%d) status=%d", item.ID, resp.StatusCode), nil)
			}
		}
		count++
		_ = r.History.Append("ssdeep.ok", fmt.Sprintf("imported %s (%d signatures, v=%s)", fileName, total, item.Version), map[string]any{
			"ssdeep_id": item.ID,
			"count":     total,
		})
	}
	if count > 0 && r.Scan != nil {
		r.Scan.RefreshSsdeep()
	}
	return count
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
