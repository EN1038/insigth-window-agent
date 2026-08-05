package ipc

import "github.com/sosecure/insite-agent/internal/config"

type StatusResponse struct {
	HasConfig        bool    `json:"has_config"`
	Approved         bool    `json:"approved"`
	ThreatIntelReady bool    `json:"threat_intel_ready"`
	SyncBusy         bool    `json:"sync_busy"`
	DownloadPercent  float64 `json:"download_percent"`
	DownloadMessage  string  `json:"download_message"`
	LoggedIn         bool    `json:"logged_in"`
	Online           bool    `json:"online"`
	AgentID          string  `json:"agent_id"`
	Scanning         bool    `json:"scanning"`
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
	Scanning    bool   `json:"scanning"`
	ScanType    string `json:"scan_type"`
	Scanned     int    `json:"scanned"`
	Total       int    `json:"total"`
	Skipped     int    `json:"skipped"`
	Threats     int    `json:"threats"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	CurrentFile string `json:"current_file"`
}

type SettingsView struct {
	RealtimeShield      bool   `json:"realtime_shield"`
	USBProtection       bool   `json:"usb_protection"`
	AutoScanOnLogin     bool   `json:"auto_scan_on_login"`
	BatchJobEveryDay    string `json:"batchjob_everydate"`
	TISyncEveryDay      string `json:"ti_sync_everydate"`
	AgentUpdateSchedule string `json:"agent_update_schedule"`
	AgentVersionCurrent string `json:"agent_version_current"`
	AgentVersionTarget  string `json:"agent_version_target"`
	AgentUpdateStatus   string `json:"agent_update_status"`
	ExclusionPaths      string `json:"exclusion_paths"`
	ScanExtensions      string `json:"scan_extensions"`
	QuickScanPaths      string `json:"quick_scan_paths"`
	SsdeepEnabled       bool   `json:"ssdeep_enabled"`
	SsdeepThreshold     string `json:"ssdeep_threshold"`
	SsdeepReportAPI     bool   `json:"ssdeep_report_api"`
	QuarantineOnDetect  bool   `json:"quarantine_on_detect"`
	SendSsdeepCandidate bool   `json:"send_ssdeep_candidate"`
	LogLevel            string `json:"log_level"`
	CacheExpiryHours    string `json:"cache_expiry_hours"`
	RulesVersion        string `json:"rules_version"`
	ServerRulesCount    string `json:"server_rules_count"`
	LocalRulesCount     string `json:"local_rules_count"`
	SsdeepDBVersion     string `json:"ssdeep_db_version"`
	LastTISyncRun       string `json:"last_ti_sync_run"`
}

type UpdateSettingsRequest struct {
	RealtimeShield      *bool  `json:"realtime_shield,omitempty"`
	USBProtection       *bool  `json:"usb_protection,omitempty"`
	AutoScanOnLogin     *bool  `json:"auto_scan_on_login,omitempty"`
	BatchJobEveryDay    string `json:"batchjob_everydate,omitempty"`
	TISyncEveryDay      string `json:"ti_sync_everydate,omitempty"`
	AgentUpdateSchedule string `json:"agent_update_schedule,omitempty"`
	ExclusionPaths      *string `json:"exclusion_paths,omitempty"`
	ScanExtensions      string `json:"scan_extensions,omitempty"`
	QuickScanPaths      *string `json:"quick_scan_paths,omitempty"`
	SsdeepEnabled       *bool  `json:"ssdeep_enabled,omitempty"`
	SsdeepThreshold     string `json:"ssdeep_threshold,omitempty"`
	SsdeepReportAPI     *bool  `json:"ssdeep_report_api,omitempty"`
	QuarantineOnDetect  *bool  `json:"quarantine_on_detect,omitempty"`
	SendSsdeepCandidate *bool  `json:"send_ssdeep_candidate,omitempty"`
	LogLevel            string `json:"log_level,omitempty"`
	CacheExpiryHours    string `json:"cache_expiry_hours,omitempty"`
}

type HistoryEvent struct {
	Time    string `json:"time"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type RulesInfoResponse struct {
	Version      string `json:"version"`
	Count        int    `json:"count"`
	ServerCount  int    `json:"server_count"`
	LocalCount   int    `json:"local_count"`
	UpdatedAt    string `json:"updated_at"`
	BehindServer bool   `json:"behind_server"`
}

type SsdeepInfoResponse struct {
	Enabled   bool   `json:"enabled"`
	Version   string `json:"version"`
	Total     int    `json:"total"`
	Shards    int    `json:"shards"`
	UpdatedAt string `json:"updated_at"`
	Threshold string `json:"threshold"`
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
