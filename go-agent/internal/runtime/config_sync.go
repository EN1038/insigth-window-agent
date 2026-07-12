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
		ID int64 `json:"id"`
	} `json:"agent"`
	RealTimeProtection any `json:"real_time_protection"`
	USBProtection      any `json:"usb_protection"`
	BatchJobEveryDate    any `json:"batchjob_everydate"`
	ScanExtensions     any `json:"scan_extensions"`
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

	if v, ok := parseOnOff(cfg.RealTimeProtection); ok {
		st.Set(settings.KeyRealtimeShield, boolStr(v))
	}
	if v, ok := parseOnOff(cfg.USBProtection); ok {
		st.Set(settings.KeyUSBProtection, boolStr(v))
	}
	if batch := stringify(cfg.BatchJobEveryDate); batch != "" {
		st.Set(settings.KeyBatchJobEveryDay, batch)
	}
	if ext := parseExtensions(cfg.ScanExtensions); ext != "" {
		st.Set(settings.KeyScanExtensions, ext)
	}

	return st.Save()
}

func parseOnOff(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case float64:
		return int(t) == 1, true
	case string:
		s := strings.TrimSpace(t)
		if s == "1" || strings.EqualFold(s, "true") {
			return true, true
		}
		if s == "0" || strings.EqualFold(s, "false") {
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
		return strconv.FormatInt(int64(t), 10)
	case bool:
		if t {
			return "1"
		}
		return "0"
	default:
		return ""
	}
}

func parseExtensions(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(stringify(item))
			if s == "" {
				continue
			}
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}
