package config

// AgentConfig matches the legacy .NET config.json schema (system_client_site_*).
type AgentConfig struct {
	SiteIP   string `json:"system_client_site_ip"`
	SiteID   string `json:"system_client_site_id"`
	SiteKey  string `json:"system_client_site_key"`
	SiteName string `json:"system_client_site_name"`

	// Center AES salts (site.ip_key / site.mac_address_key). Filled via getSiteCrypto.
	SiteIPKey  string `json:"system_client_site_ip_key,omitempty"`
	SiteMacKey string `json:"system_client_site_mac_key,omitempty"`

	// Optional mTLS client certificate (PKCS#12).
	ClientCertPath string `json:"system_client_cert_path,omitempty"`
	ClientCertPass string `json:"system_client_cert_pass,omitempty"`

	// When true, skip TLS server certificate verification (legacy default).
	TLSInsecureSkipVerify bool `json:"system_client_tls_insecure,omitempty"`
}
