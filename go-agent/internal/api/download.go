package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// DownloadFile fetches a remote file using Bearer SITE_KEY auth (legacy parity).
func (c *Client) DownloadFile(url, destPath string) error {
	if c == nil || c.cfg == nil {
		return fmt.Errorf("invalid client")
	}
	if strings.HasPrefix(url, "/") {
		url = strings.TrimRight(c.cfg.SiteIP, "/") + url
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

	tmp := destPath + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, destPath)
}
