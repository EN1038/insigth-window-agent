package ipc

import "github.com/sosecure/insite-agent/internal/config"

type StatusResponse struct {
	HasConfig bool   `json:"has_config"`
	Approved  bool   `json:"approved"`
	LoggedIn  bool   `json:"logged_in"`
	Online    bool   `json:"online"`
	AgentID   string `json:"agent_id"`
	Scanning  bool   `json:"scanning"`
}

type ConfigView struct {
	SiteIP   string `json:"site_ip"`
	SiteID   string `json:"site_id"`
	SiteKey  string `json:"site_key"`
	SiteName string `json:"site_name"`
}

type SaveConfigRequest struct {
	SiteIP  string `json:"site_ip"`
	SiteID  string `json:"site_id"`
	SiteKey string `json:"site_key"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	AgentID string `json:"agent_id"`
}

type ScanStartRequest struct {
	Type string `json:"type"` // quick|full|custom|auto
	Path string `json:"path,omitempty"`
}

type ScanStatusResponse struct {
	Scanning bool   `json:"scanning"`
	ScanType string `json:"scan_type"`
	Scanned  int    `json:"scanned"`
	Total    int    `json:"total"`
	Skipped  int    `json:"skipped"`
	Threats  int    `json:"threats"`
	Status   string `json:"status"`
}

type SettingsView struct {
	RealtimeShield   bool   `json:"realtime_shield"`
	USBProtection    bool   `json:"usb_protection"`
	AutoScanOnLogin  bool   `json:"auto_scan_on_login"`
	BatchJobEveryDay string `json:"batchjob_everydate"`
	ExclusionPaths   string `json:"exclusion_paths"`
	RulesVersion     string `json:"rules_version"`
}

type UpdateSettingsRequest struct {
	RealtimeShield   *bool  `json:"realtime_shield,omitempty"`
	USBProtection    *bool  `json:"usb_protection,omitempty"`
	AutoScanOnLogin  *bool  `json:"auto_scan_on_login,omitempty"`
	BatchJobEveryDay string `json:"batchjob_everydate,omitempty"`
	ExclusionPaths   string `json:"exclusion_paths,omitempty"`
}

type HistoryEvent struct {
	Time    string `json:"time"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type RulesInfoResponse struct {
	Version   string `json:"version"`
	Count     int    `json:"count"`
	UpdatedAt string `json:"updated_at"`
}

type QuarantineItem struct {
	ID           string `json:"id"`
	FileName     string `json:"file_name"`
	OriginalPath string `json:"original_path"`
	ThreatType   string `json:"threat_type"`
	IsolatedAt   string `json:"isolated_at"`
}

type OKResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func ConfigToView(cfg *config.AgentConfig) ConfigView {
	if cfg == nil {
		return ConfigView{}
	}
	return ConfigView{
		SiteIP:   cfg.SiteIP,
		SiteID:   cfg.SiteID,
		SiteKey:  cfg.SiteKey,
		SiteName: cfg.SiteName,
	}
}

// ConfigToPublicView returns config safe for the UI: site key is never exposed.
func ConfigToPublicView(cfg *config.AgentConfig) ConfigView {
	v := ConfigToView(cfg)
	v.SiteKey = ""
	return v
}
