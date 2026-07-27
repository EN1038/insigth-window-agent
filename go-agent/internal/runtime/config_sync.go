package runtime

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sosecure/insite-agent/internal/settings"
)

type serverConfigPayload struct {
	Agent struct {
		ID                  int64 `json:"id"`
		RealTimeProtection  any   `json:"real_time_protection"`
		USBProtection       any   `json:"usb_protection"`
		BatchJobEveryDate   any   `json:"batchjob_everydate"`
		SsdeepEnabled       any   `json:"ssdeep_enabled"`
		SsdeepThreshold     any   `json:"ssdeep_threshold"`
		SsdeepReportAPI     any   `json:"ssdeep_report_api"`
		QuarantineOnDetect  any   `json:"quarantine_on_detect"`
		SendSsdeepCandidate any   `json:"send_ssdeep_candidate"`
		AutoScanOnLogin     any   `json:"auto_scan_on_login"`
		ExclusionPaths      any   `json:"exclusion_paths"`
		ScanExtensions      any   `json:"scan_extensions"`
		QuickScanPaths      any   `json:"quick_scan_paths"`
		LogLevel            any   `json:"log_level"`
		CacheExpiryHours    any   `json:"cache_expiry_hours"`
		ConfigUpdatedAt     any   `json:"config_updated_at"`
	} `json:"agent"`
	RealTimeProtection  any `json:"real_time_protection"`
	USBProtection       any `json:"usb_protection"`
	BatchJobEveryDate   any `json:"batchjob_everydate"`
	ScanExtensions      any `json:"scan_extensions"`
	Extentions          any `json:"extentions"` // Center typo / legacy key
	ExclusionPaths      any `json:"exclusion_paths"`
	QuickScanPaths      any `json:"quick_scan_paths"`
	AutoScanOnLogin     any `json:"auto_scan_on_login"`
	SsdeepEnabled       any `json:"ssdeep_enabled"`
	SsdeepThreshold     any `json:"ssdeep_threshold"`
	SsdeepReportAPI     any `json:"ssdeep_report_api"`
	SsdeepDBVersion     any `json:"ssdeep_db_version"`
	QuarantineOnDetect  any `json:"quarantine_on_detect"`
	SendSsdeepCandidate any `json:"send_ssdeep_candidate"`
	LogLevel            any `json:"log_level"`
	CacheExpiryHours    any `json:"cache_expiry_hours"`
	ConfigUpdatedAt     any `json:"config_updated_at"`
}

func applyGetConfig(st *settings.Store, data json.RawMessage) error {
	if st == nil || len(data) == 0 || string(data) == "null" {
		return nil
	}

	var cfg serverConfigPayload
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	if cfg.Agent.ID > 0 {
		st.Set(keyAgentID, fmt.Sprintf("%d", cfg.Agent.ID))
	}

	// Last-write-wins: skip policy fields when local edit is newer than Center.
	serverTs := parseUnixTS(firstNonNil(cfg.ConfigUpdatedAt, cfg.Agent.ConfigUpdatedAt))
	localTs := parseUnixTS(st.Get(settings.KeyConfigUpdatedAt, "0"))
	if serverTs > 0 && localTs > 0 && serverTs <= localTs {
		return st.Save()
	}

	rtp := firstNonNil(cfg.RealTimeProtection, cfg.Agent.RealTimeProtection)
	if v, ok := parseOnOff(rtp); ok {
		st.Set(settings.KeyRealtimeShield, boolStr(v))
	}
	usb := firstNonNil(cfg.USBProtection, cfg.Agent.USBProtection)
	if v, ok := parseOnOff(usb); ok {
		st.Set(settings.KeyUSBProtection, boolStr(v))
	}
	batch := firstNonNil(cfg.BatchJobEveryDate, cfg.Agent.BatchJobEveryDate)
	if b := stringify(batch); b != "" {
		st.Set(settings.KeyBatchJobEveryDay, b)
	}

	autoLogin := firstNonNil(cfg.AutoScanOnLogin, cfg.Agent.AutoScanOnLogin)
	if v, ok := parseOnOff(autoLogin); ok {
		st.Set(settings.KeyAutoScanOnLogin, boolStr(v))
	}

	excl := firstNonNil(cfg.ExclusionPaths, cfg.Agent.ExclusionPaths)
	if s := normalizePathList(stringify(excl)); s != "" {
		st.Set(settings.KeyExclusionPaths, s)
	}

	// Prefer explicit scan_extensions; fall back to Center extentions list.
	extSrc := firstNonNil(cfg.ScanExtensions, cfg.Agent.ScanExtensions, cfg.Extentions)
	if ext := parseExtensions(extSrc); ext != "" {
		st.Set(settings.KeyScanExtensions, ext)
	}
	_ = st.MergeDefaultScanExtensions()

	quick := firstNonNil(cfg.QuickScanPaths, cfg.Agent.QuickScanPaths)
	if s := normalizePathList(stringify(quick)); s != "" {
		st.Set(settings.KeyQuickScanPaths, s)
	}

	ssdeepOn := firstNonNil(cfg.SsdeepEnabled, cfg.Agent.SsdeepEnabled)
	if v, ok := parseOnOff(ssdeepOn); ok {
		st.Set(settings.KeySsdeepEnabled, boolStr(v))
	}
	ssdeepThr := firstNonNil(cfg.SsdeepThreshold, cfg.Agent.SsdeepThreshold)
	if threshold := stringify(ssdeepThr); threshold != "" {
		st.Set(settings.KeySsdeepThreshold, threshold)
	}
	ssdeepReport := firstNonNil(cfg.SsdeepReportAPI, cfg.Agent.SsdeepReportAPI)
	if v, ok := parseOnOff(ssdeepReport); ok {
		st.Set(settings.KeySsdeepReportAPI, boolStr(v))
	}
	if version := stringify(cfg.SsdeepDBVersion); version != "" {
		st.Set(settings.KeySsdeepDBVersion, version)
	}
	quarantine := firstNonNil(cfg.QuarantineOnDetect, cfg.Agent.QuarantineOnDetect)
	if v, ok := parseOnOff(quarantine); ok {
		st.Set(settings.KeyQuarantineOnDetect, boolStr(v))
	}
	sendCand := firstNonNil(cfg.SendSsdeepCandidate, cfg.Agent.SendSsdeepCandidate)
	if v, ok := parseOnOff(sendCand); ok {
		st.Set(settings.KeySendSsdeepCandidate, boolStr(v))
	}

	logLevel := firstNonNil(cfg.LogLevel, cfg.Agent.LogLevel)
	if s := strings.ToLower(strings.TrimSpace(stringify(logLevel))); s != "" {
		if s == "warning" {
			s = "warn"
		}
		st.Set(settings.KeyLogLevel, s)
	}
	cacheHours := firstNonNil(cfg.CacheExpiryHours, cfg.Agent.CacheExpiryHours)
	if s := stringify(cacheHours); s != "" {
		st.Set(settings.KeyCacheExpiryHours, s)
	}

	if serverTs > 0 {
		st.Set(settings.KeyConfigUpdatedAt, fmt.Sprintf("%d", serverTs))
	}

	return st.Save()
}

func parseUnixTS(v any) int64 {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		if t <= 0 {
			return 0
		}
		return int64(t)
	case int64:
		if t <= 0 {
			return 0
		}
		return t
	case int:
		if t <= 0 {
			return 0
		}
		return int64(t)
	case string:
		s := strings.TrimSpace(t)
		if s == "" || s == "0" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return n
	case json.Number:
		n, err := t.Int64()
		if err != nil || n <= 0 {
			return 0
		}
		return n
	default:
		s := stringify(v)
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return n
	}
}

func firstNonNil(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func parseOnOff(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case float64:
		return int(t) != 0, true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return false, false
		}
		return n != 0, true
	case string:
		s := strings.TrimSpace(t)
		if s == "1" || strings.EqualFold(s, "true") || strings.EqualFold(s, "y") || strings.EqualFold(s, "on") {
			return true, true
		}
		if s == "0" || strings.EqualFold(s, "false") || strings.EqualFold(s, "n") || strings.EqualFold(s, "off") {
			return false, true
		}
	}
	return false, false
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "1"
		}
		return "0"
	default:
		return ""
	}
}

func normalizePathList(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "\r\n", ";")
	raw = strings.ReplaceAll(raw, "\n", ";")
	raw = strings.ReplaceAll(raw, "\r", ";")
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ";")
}

func parseExtensions(v any) string {
	switch t := v.(type) {
	case string:
		return normalizeExtensionsCSV(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			s := extensionFromItem(item)
			if s == "" {
				continue
			}
			parts = append(parts, s)
		}
		return strings.Join(uniqueStrings(parts), ",")
	default:
		return ""
	}
}

func normalizeExtensionsCSV(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", ",")
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, ".") {
			p = "." + p
		}
		out = append(out, p)
	}
	return strings.Join(uniqueStrings(out), ",")
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func extensionFromItem(item any) string {
	switch t := item.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return ""
		}
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		return strings.ToLower(s)
	case map[string]any:
		name := strings.TrimSpace(stringify(t["name"]))
		if name == "" {
			return ""
		}
		if !strings.HasPrefix(name, ".") {
			name = "." + name
		}
		return strings.ToLower(name)
	default:
		s := strings.TrimSpace(stringify(item))
		if s == "" {
			return ""
		}
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		return strings.ToLower(s)
	}
}
