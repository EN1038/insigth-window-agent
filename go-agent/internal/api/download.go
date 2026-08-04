package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
)

// DownloadFile fetches a remote TI pack. Prefers authenticated encrypted API;
// falls back to legacy Bearer GET for absolute/relative static URLs.
func (c *Client) DownloadFile(url, destPath string) error {
	return c.DownloadFileWithProgress(url, destPath, "", 0, 0)
}

func (c *Client) DownloadFileWithProgress(url, destPath, phase string, fileIndex, fileTotal int) error {
	if c == nil || c.cfg == nil {
		return fmt.Errorf("invalid client")
	}
	kind := "rule"
	lower := strings.ToLower(url)
	if strings.Contains(lower, "ssdeep") {
		kind = "ssdeep"
	}

	rel := url
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		if i := strings.Index(url, "://"); i >= 0 {
			rest := url[i+3:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				rel = rest[slash:]
			}
		}
	}
	rel = strings.TrimPrefix(rel, "/")
	if strings.HasPrefix(rel, "rule_files/") || strings.HasPrefix(rel, "ssdeep_files/") {
		c.reportProgress(Progress{
			Phase:     phase,
			Message:   fmt.Sprintf("Downloading %s (%d/%d)", path.Base(rel), fileIndex, fileTotal),
			FileIndex: fileIndex,
			FileTotal: fileTotal,
		})
		if err := c.DownloadProtectedFile(kind, rel, destPath); err == nil {
			return nil
		} else {
			// Prefer the authenticated error (e.g. 404 File not found). Falling through to
			// /storage/rules/... only produces a misleading Laravel HTML 404 page.
			return err
		}
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		base := strings.TrimRight(c.cfg.SiteIP, "/")
		if strings.HasPrefix(url, "/") {
			url = base + url
		} else if strings.HasPrefix(url, "storage/") {
			url = base + "/" + url
		} else {
			url = base + "/storage/rules/" + url
		}
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.SiteKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("download status %d: %s", resp.StatusCode, string(b))
	}

	total := resp.ContentLength
	tmp := destPath + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	buf := make([]byte, 32*1024)
	var read int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				_ = f.Close()
				_ = os.Remove(tmp)
				return werr
			}
			read += int64(n)
			pct := 0.0
			if total > 0 {
				pct = float64(read) * 100 / float64(total)
			}
			c.reportProgress(Progress{
				Phase:      phase,
				Message:    fmt.Sprintf("Downloading %s (%d/%d)", path.Base(destPath), fileIndex, fileTotal),
				FileIndex:  fileIndex,
				FileTotal:  fileTotal,
				BytesRead:  read,
				BytesTotal: total,
				Percent:    pct,
			})
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return readErr
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, destPath)
}
