package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/storage"
)

// Keys mirrored from the legacy .NET SettingsStore for compatibility.
const (
	KeyYaraRulesPath    = "yara_rules_path"
	KeyYaraEnginePath   = "yara_engine_path"
	KeyRulesVersion     = "rules_version"
	KeyQuarantinePath   = "quarantine_path"
	KeyLogLevel         = "log_level"
	KeyScanExtensions   = "scan_extensions"
	KeyExclusionPaths   = "exclusion_paths"
	KeyCacheExpiryHours = "cache_expiry_hours"
	KeyQuickScanPaths   = "quick_scan_paths"
	KeyAutoScanOnLogin  = "auto_scan_on_login"
	KeyUSBProtection    = "usb_protection"
	KeyRealtimeShield   = "realtime_shield"
	KeyBatchJobEveryDay = "batchjob_everydate"
	KeyLastBatchJobRun  = "last_batchjob_run"
	KeyAPISecret        = "api_secret"
)

type Store struct {
	baseDir string
	paths   config.Paths

	Values map[string]string `json:"values"`
}

func New(baseDir string) *Store {
	p := config.ResolvePaths(baseDir)
	s := &Store{
		baseDir: baseDir,
		paths:   p,
		Values:  map[string]string{},
	}
	s.setDefaults()
	return s
}

func (s *Store) setDefaults() {
	def := func(k, v string) {
		if _, ok := s.Values[k]; !ok {
			s.Values[k] = v
		}
	}
	def(KeyYaraRulesPath, "") // rules served from encrypted store (Data/rules/*.blobenc)
	def(KeyYaraEnginePath, filepath.Join(config.InstallDir(), "Engine", "Yara", "yara64.exe"))
	def(KeyRulesVersion, "1.1")
	def(KeyQuarantinePath, filepath.Join(s.baseDir, "Quarantine"))
	def(KeyLogLevel, "info")
	def(KeyScanExtensions, ".exe,.dll,.sys,.bat,.ps1,.cmd,.vbs,.js,.wsf,.scr,.com,.pif,.php,.asp,.aspx,.jsp,.html,.htm,.inc,.tpl")
	def(KeyExclusionPaths, `\windows;\$recycle.bin;\system volume information;\program files;\program files (x86);\programdata`)
	def(KeyCacheExpiryHours, "168")
	def(KeyQuickScanPaths, `%USERPROFILE%\Downloads;%USERPROFILE%\Desktop;%TEMP%;%APPDATA%`)
	def(KeyAutoScanOnLogin, "true")
	def(KeyUSBProtection, "true")
	def(KeyRealtimeShield, "true")
	def(KeyBatchJobEveryDay, "02:00")
	def(KeyAPISecret, "")
}

func (s *Store) Load() error {
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "settings.enc"),
		Purpose:   "settings",
		AAD:       "settings|v1",
	}
	type payload struct {
		Values map[string]string `json:"values"`
	}
	var p payload
	if err := enc.Load(&p); err != nil {
		// If missing, attempt migrate legacy settings.cfg (encrypted/plain), then save.
		if os.IsNotExist(err) {
			_ = s.migrateLegacySettingsCfg(filepath.Join(s.paths.DataDir, "settings.cfg"))
			_ = s.Save()
			return nil
		}
		return err
	}
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	s.Values = p.Values
	s.setDefaults()
	return nil
}

func (s *Store) Save() error {
	s.setDefaults()
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "settings.enc"),
		Purpose:   "settings",
		AAD:       "settings|v1",
	}
	type payload struct {
		Values map[string]string `json:"values"`
	}
	return enc.Save(payload{Values: s.Values})
}

func (s *Store) Get(key, def string) string {
	if v, ok := s.Values[key]; ok {
		return v
	}
	return def
}

func (s *Store) Set(key, val string) {
	if s.Values == nil {
		s.Values = map[string]string{}
	}
	s.Values[key] = val
}

func (s *Store) GetBool(key string) bool {
	return strings.EqualFold(s.Get(key, "false"), "true")
}

func (s *Store) Exclusions() []string {
	raw := s.Get(KeyExclusionPaths, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) ScanExtensions() []string {
	raw := s.Get(KeyScanExtensions, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, ".") {
			p = "." + p
		}
		out = append(out, strings.ToLower(p))
	}
	return out
}

func (s *Store) QuickScanPaths() []string {
	raw := s.Get(KeyQuickScanPaths, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(os.ExpandEnv(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) migrateLegacySettingsCfg(path string) error {
	// Minimal migration: only handle plaintext key=value format.
	// (Legacy .NET used AES wrapper; we'll extend migration later if needed.)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		eq := strings.IndexByte(ln, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:eq])
		v := strings.TrimSpace(ln[eq+1:])
		if k != "" {
			s.Set(k, v)
		}
	}
	s.setDefaults()
	return nil
}

func (s *Store) Validate() error {
	if s.Get(KeyBatchJobEveryDay, "") == "" {
		return fmt.Errorf("missing batchjob_everydate")
	}
	return nil
}

