package api

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

type Client struct {
	cfg  *config.AgentConfig
	http *http.Client

	mu       sync.Mutex
	progress ProgressFunc
}

type ProgressFunc func(p Progress)

type Progress struct {
	Phase      string  // rules | ssdeep | file
	Message    string
	FileIndex  int
	FileTotal  int
	BytesRead  int64
	BytesTotal int64
	Percent    float64
}

type Response struct {
	Error      string          `json:"error"`
	StatusCode int             `json:"status_code"`
	Data       json.RawMessage `json:"data"`
}

func New(cfg *config.AgentConfig) *Client {
	tr := &http.Transport{
		TLSClientConfig: buildTLSConfig(cfg),
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   120 * time.Second,
			Transport: tr,
		},
	}
}

func buildTLSConfig(cfg *config.AgentConfig) *tls.Config {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	certPath, certPass := resolveClientCert(cfg)
	insecure := true
	if cfg != nil {
		insecure = cfg.TLSInsecureSkipVerify || certPath == ""
		if !cfg.TLSInsecureSkipVerify && certPath != "" {
			insecure = false
		}
	}
	if certPath != "" {
		if cert, err := loadPKCS12(certPath, certPass); err == nil {
			tlsCfg.Certificates = []tls.Certificate{*cert}
		}
	}
	tlsCfg.InsecureSkipVerify = insecure
	return tlsCfg
}

func resolveClientCert(cfg *config.AgentConfig) (path, pass string) {
	if cfg != nil && strings.TrimSpace(cfg.ClientCertPath) != "" {
		return strings.TrimSpace(cfg.ClientCertPath), cfg.ClientCertPass
	}
	if p := strings.TrimSpace(os.Getenv("INSITE_CLIENT_CERT_PATH")); p != "" {
		return p, os.Getenv("INSITE_CLIENT_CERT_PASS")
	}
	def := filepath.Join(config.DataBaseDir(), "Config", "Key", "client.p12")
	if _, err := os.Stat(def); err == nil {
		return def, os.Getenv("INSITE_CLIENT_CERT_PASS")
	}
	return "", ""
}

func loadPKCS12(path, password string) (*tls.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	priv, cert, ca, err := pkcs12.DecodeChain(b, password)
	if err != nil {
		// Fallback: some exporters use Decode only.
		priv2, cert2, err2 := pkcs12.Decode(b, password)
		if err2 != nil {
			return nil, err
		}
		priv, cert, ca = priv2, cert2, nil
	}
	var chain [][]byte
	chain = append(chain, cert.Raw)
	for _, c := range ca {
		chain = append(chain, c.Raw)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}

func (c *Client) SetProgressFunc(fn ProgressFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.progress = fn
}

func (c *Client) reportProgress(p Progress) {
	c.mu.Lock()
	fn := c.progress
	c.mu.Unlock()
	if fn != nil {
		fn(p)
	}
}

func (c *Client) endpointURL(endpoint string) string {
	base := strings.TrimRight(c.cfg.SiteIP, "/")
	code := strings.Trim(c.cfg.SiteID, "/")
	// Agent talks to Site API Client, which proxies/encrypts toward Center.
	return base + "/api/" + code + "/agentClient/" + endpoint
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
		return nil, raw, fmt.Errorf("decode response: %w", err)
	}
	if r.Error == "" && r.StatusCode >= 400 {
		r.Error = http.StatusText(r.StatusCode)
	}
	if r.StatusCode == 0 && resp.StatusCode == http.StatusOK {
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
func (c *Client) UpdateConfig(batchHHmm string, realtime int, usb int, extra map[string]any) (*Response, []byte, error) {
	payload := map[string]any{
		"ip_private":           sysinfo.LocalIPv4(),
		"batchjob_everydate":   batchHHmm,
		"real_time_protection": realtime,
		"usb_protection":       usb,
	}
	for k, v := range extra {
		if k == "" || v == nil {
			continue
		}
		payload[k] = v
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
	AgentID     int64  `json:"agent_id"`
	Description string `json:"description"`
	TimeStamp   string `json:"time_stamp"`
	Mode        string `json:"mode"`
	Type        string `json:"type"` // start|end
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
		"ip_private": sysinfo.LocalIPv4(),
		"candidates": items,
	}
	return c.postJSON("sendSsdeepCandidate", payload)
}

// DownloadProtectedFile fetches a pack via authenticated encrypted API (preferred over static URLs).
func (c *Client) DownloadProtectedFile(kind, path string, destPath string) error {
	payload := map[string]any{
		"kind": kind,
		"path": path,
	}
	resp, _, err := c.postJSON("downloadProtectedFile", payload)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("downloadProtectedFile status %d: %s", resp.StatusCode, resp.Error)
	}
	var body struct {
		FileName   string `json:"file_name"`
		ContentB64 string `json:"content_b64"`
	}
	if err := json.Unmarshal(resp.Data, &body); err != nil {
		return err
	}
	if body.ContentB64 == "" {
		return fmt.Errorf("empty file content")
	}
	raw, err := base64.StdEncoding.DecodeString(body.ContentB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(body.ContentB64)
		if err != nil {
			return err
		}
	}
	c.reportProgress(Progress{
		Phase:      "file",
		Message:    "Saving " + body.FileName,
		BytesTotal: int64(len(raw)),
		BytesRead:  int64(len(raw)),
		Percent:    100,
	})
	tmp := destPath + ".part"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, destPath)
}
