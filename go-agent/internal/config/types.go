package config

// AgentConfig matches the legacy .NET config.json schema (system_client_site_*).
type AgentConfig struct {
	SiteIP   string `json:"system_client_site_ip"`
	SiteID   string `json:"system_client_site_id"`
	SiteKey  string `json:"system_client_site_key"`
	SiteName string `json:"system_client_site_name"`
}

