package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
)

type Client struct {
	base   string
	token  string
	client *http.Client
}

func NewClient(addr string) *Client {
	if addr == "" {
		addr = DefaultAddr
	}
	c := &Client{
		base: "http://" + addr,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	if tok, err := LoadLocalToken(config.DataBaseDir()); err == nil {
		c.token = tok
	}
	return c
}

// SetToken overrides the local IPC auth token (tests / custom base dir).
func (c *Client) SetToken(token string) {
	c.token = strings.TrimSpace(token)
}

func (c *Client) Health(ctx context.Context) error {
	var out OKResponse
	return c.get(ctx, "/v1/health", &out)
}

func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	err := c.get(ctx, "/v1/status", &out)
	return out, err
}

func (c *Client) GetConfig(ctx context.Context) (ConfigView, error) {
	var out ConfigView
	err := c.get(ctx, "/v1/config", &out)
	return out, err
}

func (c *Client) SaveConfig(ctx context.Context, req SaveConfigRequest) (OKResponse, error) {
	var out OKResponse
	err := c.post(ctx, "/v1/config", req, &out)
	return out, err
}

func (c *Client) TestConnection(ctx context.Context) (bool, error) {
	var out OKResponse
	if err := c.post(ctx, "/v1/connection/test", map[string]any{}, &out); err != nil {
		return false, err
	}
	return out.OK, nil
}

func (c *Client) Login(ctx context.Context, email, password string) (LoginResponse, error) {
	var out LoginResponse
	err := c.post(ctx, "/v1/login", LoginRequest{Email: email, Password: password}, &out)
	return out, err
}

func (c *Client) Logout(ctx context.Context) error {
	var out OKResponse
	return c.post(ctx, "/v1/logout", map[string]any{}, &out)
}

func (c *Client) GetSettings(ctx context.Context) (SettingsView, error) {
	var out SettingsView
	err := c.get(ctx, "/v1/settings", &out)
	return out, err
}

func (c *Client) UpdateSettings(ctx context.Context, req UpdateSettingsRequest) error {
	var out OKResponse
	return c.post(ctx, "/v1/settings", req, &out)
}

func (c *Client) StartScan(ctx context.Context, scanType, path string) (OKResponse, error) {
	var out OKResponse
	err := c.post(ctx, "/v1/scan/start", ScanStartRequest{Type: scanType, Path: path}, &out)
	return out, err
}

func (c *Client) StopScan(ctx context.Context) error {
	var out OKResponse
	return c.post(ctx, "/v1/scan/stop", map[string]any{}, &out)
}

func (c *Client) ScanStatus(ctx context.Context) (ScanStatusResponse, error) {
	var out ScanStatusResponse
	err := c.get(ctx, "/v1/scan/status", &out)
	return out, err
}

func (c *Client) SyncRules(ctx context.Context) error {
	var out OKResponse
	return c.post(ctx, "/v1/rules/sync", map[string]any{}, &out)
}

func (c *Client) CheckAgentUpdate(ctx context.Context) (OKResponse, error) {
	var out OKResponse
	err := c.post(ctx, "/v1/agent/update/check", map[string]any{}, &out)
	return out, err
}

func (c *Client) InstallAgentUpdate(ctx context.Context) (OKResponse, error) {
	var out OKResponse
	err := c.post(ctx, "/v1/agent/update/install", map[string]any{}, &out)
	return out, err
}

func (c *Client) InstallService(ctx context.Context) (OKResponse, error) {
	var out OKResponse
	err := c.post(ctx, "/v1/service/install", map[string]any{}, &out)
	return out, err
}

func (c *Client) RulesInfo(ctx context.Context) (RulesInfoResponse, error) {
	var out RulesInfoResponse
	err := c.get(ctx, "/v1/rules/info", &out)
	return out, err
}

func (c *Client) SsdeepInfo(ctx context.Context) (SsdeepInfoResponse, error) {
	var out SsdeepInfoResponse
	err := c.get(ctx, "/v1/ssdeep/info", &out)
	return out, err
}

func (c *Client) Quarantine(ctx context.Context) ([]QuarantineItem, error) {
	var out []QuarantineItem
	err := c.get(ctx, "/v1/quarantine", &out)
	return out, err
}

func (c *Client) History(ctx context.Context, limit int) ([]HistoryEvent, error) {
	var out []HistoryEvent
	err := c.get(ctx, fmt.Sprintf("/v1/history?limit=%d", limit), &out)
	return out, err
}

func (c *Client) ScanRunFiles(ctx context.Context, runID string, offset, limit int) (ScanRunFilesResponse, error) {
	var out ScanRunFilesResponse
	if limit <= 0 {
		limit = 200
	}
	err := c.get(ctx, fmt.Sprintf("/v1/scan/files?run_id=%s&offset=%d&limit=%d", url.QueryEscape(runID), offset, limit), &out)
	return out, err
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	if c.token != "" {
		req.Header.Set(tokenHeader, c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ipc %s %s: %s", req.Method, req.URL.Path, string(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
