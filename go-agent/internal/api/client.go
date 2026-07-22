package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

type Client struct {
	cfg  *config.AgentConfig
	http *http.Client
}

type Response struct {
	Error      string          `json:"error"`
	StatusCode int             `json:"status_code"`
	Data       json.RawMessage `json:"data"`
}

func New(cfg *config.AgentConfig) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Legacy behavior in .NET accepted all certs. Keep for parity for now.
			// We will add a strict mode flag later.
			InsecureSkipVerify: true,
		},
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   120 * time.Second,
			Transport: tr,
		},
	}
}

func (c *Client) endpointURL(endpoint string) string {
	base := strings.TrimRight(c.cfg.SiteIP, "/")
	return base + "/api/" + c.cfg.SiteID + "/agentClient/" + endpoint
}

func (c *Client) postJSON(endpoint string, body any) (*Response, []byte, error) {
	if c.cfg == nil || c.cfg.SiteIP == "" || c.cfg.SiteID == "" || c.cfg.SiteKey == "" {
		return nil, nil, fmt.Errorf("invalid config")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("POST", c.endpointURL(endpoint), bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.SiteKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var r Response
	if err := json.Unmarshal(raw, &r); err != nil {
		// If server returns non-json, still bubble up raw body for troubleshooting.
		return nil, raw, fmt.Errorf("decode response: %w", err)
	}
	if r.Error == "" && r.StatusCode >= 400 {
		r.Error = http.StatusText(r.StatusCode)
	}
	if r.StatusCode == 0 && resp.StatusCode == http.StatusOK {
		// Some deployments may not set status_code; normalize.
		r.StatusCode = 200
	}
	return &r, raw, nil
}

func (c *Client) isOK(r *Response) bool {
	return r != nil && r.StatusCode == 200
}

// DataInfo registers/refreshes machine identity (hostname, OS, hardware, IP).
func (c *Client) DataInfo() (*Response, []byte, error) {
	payload := map[string]any{
		"device_name":    sysinfo.Hostname(),
		"os_type":        "1",
		"os_description": sysinfo.OsDescription(),
		"system_info":    sysinfo.SystemInfo(),
		"domain":         sysinfo.Domain(),
		"ip_private":     sysinfo.LocalIPv4(),
	}
	return c.postJSON("dataInfo", payload)
}

// LoginAgent authenticates a user (UI flow). Caller must not persist email/password.
func (c *Client) LoginAgent(email, password string) (*Response, []byte, error) {
	payload := map[string]any{
		"email":    email,
		"password": password,
	}
	return c.postJSON("loginAgent", payload)
}

// CheckedAgentApproved checks approval status and returns server data payload.
func (c *Client) CheckedAgentApproved() (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	return c.postJSON("checkedAgentApproved", payload)
}

// GetConfig pulls the agent config object + enabled extensions from server.
func (c *Client) GetConfig() (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	return c.postJSON("getConfig", payload)
}

// UpdateConfig updates config settings back to server.
func (c *Client) UpdateConfig(batchHHmm string, realtime int, usb int) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private":           sysinfo.LocalIPv4(),
		"batchjob_everydate":   batchHHmm,
		"real_time_protection": realtime,
		"usb_protection":       usb,
	}
	return c.postJSON("updateConfig", payload)
}

// GetRule returns rule metadata list.
func (c *Client) GetRule() (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	return c.postJSON("getRule", payload)
}

// DownloadRuleSite returns list of files to download (path + rule_name + id).
func (c *Client) DownloadRuleSite() (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	return c.postJSON("downloadRuleSite", payload)
}

func (c *Client) DownloadRuleSiteComplete(id int64) (*Response, []byte, error) {
	payload := map[string]any{
		"id": id,
	}
	return c.postJSON("downloadRuleSiteComplete", payload)
}

func (c *Client) UpdateRuleDownload(agentID int64, ruleID int64) (*Response, []byte, error) {
	payload := map[string]any{
		"agent_id": agentID,
		"rule_id":  ruleID,
	}
	return c.postJSON("updateRuleDownload", payload)
}

// AgentOnlineTimestamp sends heartbeat.
func (c *Client) AgentOnlineTimestamp(isLogin bool) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
		"is_login":   isLogin,
	}
	return c.postJSON("agentOnlineTimestamp", payload)
}

type YaraLogItem struct {
	AgentID     int64  `json:"agent_id"`
	Path        string `json:"path"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	DeviceName  string `json:"device_name"`
	FileText    string `json:"file_text"`
	FirstScan   string `json:"first_scan"`
	LastScan    string `json:"last_scan"`
}

func (c *Client) SendLogYara(items []YaraLogItem) (*Response, []byte, error) {
	payload := map[string]any{
		"yara": items,
	}
	return c.postJSON("sendLogYara", payload)
}

type ScanLogItem struct {
	AgentID      int64  `json:"agent_id"`
	Description  string `json:"description"`
	TimeStamp    string `json:"time_stamp"`
	Mode         string `json:"mode"`
	Type         string `json:"type"` // start|end
}

func (c *Client) SendAgentScanLog(items []ScanLogItem) (*Response, []byte, error) {
	payload := map[string]any{
		"agent_scan": items,
	}
	return c.postJSON("sendAgentScanLog", payload)
}

type HashItem struct {
	FileName string `json:"file_name"`
	HashMD5  string `json:"hash_md5"`
	Path     string `json:"path"`
}

func (c *Client) SendHash(items []HashItem) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
		"data":       items,
	}
	return c.postJSON("sendHash", payload)
}

func (c *Client) GetSsdeep(currentVersion string) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	if strings.TrimSpace(currentVersion) != "" {
		payload["current_version"] = currentVersion
	}
	return c.postJSON("getSsdeep", payload)
}

func (c *Client) DownloadSsdeepSite(currentVersion string) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private": sysinfo.LocalIPv4(),
	}
	if strings.TrimSpace(currentVersion) != "" {
		payload["current_version"] = currentVersion
	}
	return c.postJSON("downloadSsdeepSite", payload)
}

func (c *Client) DownloadSsdeepSiteComplete(id int64) (*Response, []byte, error) {
	payload := map[string]any{
		"id": id,
	}
	return c.postJSON("downloadSsdeepSiteComplete", payload)
}

func (c *Client) UpdateSsdeepDownload(agentID, ssdeepID int64, version string) (*Response, []byte, error) {
	payload := map[string]any{
		"agent_id":  agentID,
		"ssdeep_id": ssdeepID,
	}
	if strings.TrimSpace(version) != "" {
		payload["version"] = version
	}
	return c.postJSON("updateSsdeepDownload", payload)
}

// SsdeepLogItem is for sendLogSsdeep only — does not change legacy sendLogYara / sendHash.
type SsdeepLogItem struct {
	AgentID     int64  `json:"agent_id"`
	Path        string `json:"path"`
	FileName    string `json:"file_name"`
	HashMD5     string `json:"hash_md5,omitempty"`
	Ssdeep      string `json:"ssdeep"`
	Engine      string `json:"engine"` // yara | ssdeep
	Rule        string `json:"rule"`
	Score       int    `json:"score,omitempty"`
	Description string `json:"description"`
	DeviceName  string `json:"device_name"`
	DetectedAt  string `json:"detected_at"`
}

func (c *Client) SendLogSsdeep(items []SsdeepLogItem) (*Response, []byte, error) {
	payload := map[string]any{
		"ssdeep": items,
	}
	return c.postJSON("sendLogSsdeep", payload)
}

type SsdeepCandidateItem struct {
	AgentID    int64  `json:"agent_id"`
	Path       string `json:"path"`
	FileName   string `json:"file_name"`
	HashMD5    string `json:"hash_md5,omitempty"`
	HashSHA256 string `json:"hash_sha256,omitempty"`
	Ssdeep     string `json:"ssdeep"`
	Engine     string `json:"engine"`
	Rule       string `json:"rule"`
	Score      int    `json:"score,omitempty"`
	ScanMode   string `json:"scan_mode,omitempty"`
	DetectedAt string `json:"detected_at"`
	Source     string `json:"source,omitempty"`
}

func (c *Client) SendSsdeepCandidate(items []SsdeepCandidateItem) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private":  sysinfo.LocalIPv4(),
		"candidates": items,
	}
	return c.postJSON("sendSsdeepCandidate", payload)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

