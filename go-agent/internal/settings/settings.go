package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/storage"
)

// Keys mirrored from the legacy .NET SettingsStore for compatibility.
const (
	KeyYaraRulesPath    = "yara_rules_path"
	KeyYaraEnginePath   = "yara_engine_path"
	KeyRulesVersion     = "rules_version"
	// YARA catalog counts from Center getRule vs local encrypted store.
	KeyServerRulesCount = "server_rules_count"
	KeyLocalRulesCount  = "local_rules_count"
	// KeyServerRuleFilesCount stores unique/pack file count from Center (not rule_names).
	KeyServerRuleFilesCount = "server_rule_files_count"
	KeyCenterOnline   = "center_online"
	KeyCenterOnlineAt = "center_online_at"
	KeyQuarantinePath   = "quarantine_path"
	KeyLogLevel         = "log_level"
	KeyScanExtensions   = "scan_extensions"
	KeyExclusionPaths   = "exclusion_paths"
	KeyCacheExpiryHours = "cache_expiry_hours"
	KeyQuickScanPaths   = "quick_scan_paths"
	KeyAutoScanOnLogin  = "auto_scan_on_login"
	KeyUSBProtection    = "usb_protection"
	KeyRealtimeShield   = "realtime_shield"
	// Daily / interval schedule keys (minutes as decimal string; legacy HH:mm normalized on read).
	KeyBatchJobEveryDay = "batchjob_everydate"
	KeyLastBatchJobRun  = "last_batchjob_run"
	KeyTISyncEveryDay   = "ti_sync_everydate"
	KeyLastTISyncRun    = "last_ti_sync_run"
	KeyAPISecret        = "api_secret"
	// Ssdeep secondary engine: runs only on files YARA did not flag.
	KeySsdeepEnabled   = "ssdeep_enabled"
	KeySsdeepThreshold = "ssdeep_threshold"
	KeySsdeepBundledTotal = "ssdeep_bundled_total"
	KeySsdeepReportAPI    = "ssdeep_report_api" // POST sendLogSsdeep (separate from legacy YARA APIs)
	KeySsdeepDBVersion    = "ssdeep_db_version"
	KeySendSsdeepCandidate = "send_ssdeep_candidate"
	KeyQuarantineOnDetect = "quarantine_on_detect"
	// AuthorizedServiceStop is set after successful credential confirm; allows real service stop without watchdog restart.
	KeyAuthorizedServiceStop = "authorized_service_stop"
	// StandaloneScan allows local YARA/ssdeep without server API (dev / air-gapped).
	KeyStandaloneScan = "standalone_scan"
	// ConfigUpdatedAt is unix seconds (UTC) for last-write-wins vs Center Control Agent.
	KeyConfigUpdatedAt = "config_updated_at"
	// TIBootstrapDone is set after the first post-approval rules+ssdeep download finishes
	// with no remaining failed files (empty server lists count as done).
	KeyTIBootstrapDone = "ti_bootstrap_done"
	KeyTIDownloadPercent = "ti_download_percent"
	KeyTIDownloadMessage = "ti_download_message"
	KeyTISyncBusy = "ti_sync_busy"
	// OTA agent binary update (Center-assigned target version).
	KeyAgentUpdateSchedule   = "agent_update_schedule"
	KeyAgentVersionCurrent   = "agent_version_current"
	KeyAgentVersionTarget    = "agent_version_target"
	KeyAgentUpdateStatus     = "agent_update_status"
	KeyAgentUpdateLastCheck  = "agent_update_last_check"
	KeyAgentUpdateStagedPath = "agent_update_staged_path"
	KeyAgentUpdateStagedSHA  = "agent_update_staged_sha256"
	KeyAgentUpdatePending    = "agent_update_pending"
	KeyLastAgentUpdateCheck  = "last_agent_update_check"
)

// DefaultScanExtensions is the baseline on-demand / realtime file filter.
// Includes common executable/script types plus rename-evasion suffixes used by
// webshells (e.g. c99.php saved as .txt) and alternate PHP / Windows script forms.
const DefaultScanExtensions = "" +
	".exe,.dll,.sys,.scr,.com,.pif,.msi,.cpl," +
	".bat,.cmd,.ps1,.psm1,.vbs,.vbe,.js,.jse,.wsf,.wsh,.hta," +
	".lnk,.url,.scf,.reg,.chm," +
	".php,.phtml,.php3,.php4,.php5,.php7,.phps,.phar," +
	".asp,.aspx,.ashx,.asmx,.jsp,.jspx," +
	".html,.htm,.shtml,.cfm,.cgi,.pl,.py,.rb,.sh," +
	".inc,.tpl," +
	".docm,.xlsm,.pptm,.jar," +
	".txt,.log,.bak,.old,.dat," +
	".img,.iso"

// LegacyExclusionPaths is the pre–market-AV default that blanked most of the disk
// from Full scan. Installs still on this list are upgraded once on load.
const LegacyExclusionPaths = `\windows;\$recycle.bin;\system volume information;\program files;\program files (x86);\programdata`

// DefaultExclusionPaths follows consumer AV practice: Full scan covers user data
// and Program Files, while skipping only high-churn / dangerous system areas.
const DefaultExclusionPaths = "" +
	`\$recycle.bin;` +
	`\system volume information;` +
	`\windows\winsxs;` +
	`\windows\softwaredistribution;` +
	`\windows\servicing;` +
	`\windows\assembly;` +
	`\windows\installer;` +
	`\programdata\microsoft\windows defender;` +
	`\programdata\microsoft\windows\wer`

// HardExclusions are always applied (even if the operator clears exclusion_paths).
func HardExclusions() []string {
	return []string{
		`\$recycle.bin`,
		`\system volume information`,
		`\windows\winsxs`,
		`\windows\softwaredistribution`,
		`\windows\servicing`,
	}
}

// DefaultQuickScanPaths matches typical AV "quick/fast" coverage.
const DefaultQuickScanPaths = `%USERPROFILE%\Downloads;%USERPROFILE%\Desktop;%USERPROFILE%\Documents;%TEMP%;%APPDATA%`

// LegacyQuickScanPaths is upgraded once when still at the older default.
const LegacyQuickScanPaths = `%USERPROFILE%\Downloads;%USERPROFILE%\Desktop;%TEMP%;%APPDATA%`

type Store struct {
	baseDir string
	paths   config.Paths
	mu      sync.RWMutex

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
	if s.Values == nil {
		s.Values = map[string]string{}
	}
	def := func(k, v string) {
		if _, ok := s.Values[k]; !ok {
			s.Values[k] = v
		}
	}
	def(KeyYaraRulesPath, "") // rules served from encrypted store (Data/rules/*.blobenc)
	def(KeyYaraEnginePath, filepath.Join(config.InstallDir(), "Engine", "Yara", "yara64.exe"))
	def(KeyRulesVersion, "1.1")
	def(KeyServerRulesCount, "0")
	def(KeyLocalRulesCount, "0")
	def(KeyServerRuleFilesCount, "0")
	def(KeyCenterOnline, "false")
	def(KeyCenterOnlineAt, "")
	def(KeyQuarantinePath, filepath.Join(s.baseDir, "Quarantine"))
	def(KeyLogLevel, "info")
	def(KeyScanExtensions, DefaultScanExtensions)
	def(KeyExclusionPaths, DefaultExclusionPaths)
	def(KeyCacheExpiryHours, "168")
	def(KeyQuickScanPaths, DefaultQuickScanPaths)
	def(KeyAutoScanOnLogin, "false")
	def(KeyUSBProtection, "true")
	def(KeyRealtimeShield, "true")
	def(KeyBatchJobEveryDay, strconv.Itoa(DefaultBatchIntervalMinutes))
	def(KeyTISyncEveryDay, strconv.Itoa(DefaultTISyncIntervalMinutes))
	def(KeyAPISecret, "")
	def(KeySsdeepEnabled, "true")
	def(KeySsdeepThreshold, "85")
	def(KeySsdeepReportAPI, "true")
	def(KeySsdeepDBVersion, "")
	def(KeySendSsdeepCandidate, "false")
	def(KeyQuarantineOnDetect, "true")
	def(KeyAuthorizedServiceStop, "false")
	def(KeyStandaloneScan, "false")
	def(KeyConfigUpdatedAt, "0")
	def(KeyTIBootstrapDone, "false")
	def(KeyTIDownloadPercent, "0")
	def(KeyTIDownloadMessage, "")
	def(KeyTISyncBusy, "false")
	def(KeyAgentUpdateSchedule, strconv.Itoa(DefaultAgentUpdateIntervalMinutes))
	def(KeyAgentVersionCurrent, "")
	def(KeyAgentVersionTarget, "")
	def(KeyAgentUpdateStatus, "")
	def(KeyAgentUpdateLastCheck, "")
	def(KeyAgentUpdateStagedPath, "")
	def(KeyAgentUpdateStagedSHA, "")
	def(KeyAgentUpdatePending, "false")
	def(KeyLastAgentUpdateCheck, "")
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
			s.mu.Lock()
			_ = s.migrateLegacySettingsCfg(filepath.Join(s.paths.DataDir, "settings.cfg"))
			_ = s.mergeDefaultScanExtensionsLocked()
			_ = s.migrateMarketScanDefaultsLocked()
			s.mu.Unlock()
			_ = s.Save()
			return nil
		}
		return err
	}
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	s.mu.Lock()
	s.Values = p.Values
	s.setDefaults()
	changed := s.mergeDefaultScanExtensionsLocked()
	if s.migrateMarketScanDefaultsLocked() {
		changed = true
	}
	s.mu.Unlock()
	if changed {
		_ = s.Save()
	}
	return nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	s.setDefaults()
	values := make(map[string]string, len(s.Values))
	for k, v := range s.Values {
		values[k] = v
	}
	s.mu.Unlock()
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "settings.enc"),
		Purpose:   "settings",
		AAD:       "settings|v1",
	}
	type payload struct {
		Values map[string]string `json:"values"`
	}
	return enc.Save(payload{Values: values})
}

func (s *Store) Get(key, def string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.Values[key]; ok {
		return v
	}
	return def
}

func (s *Store) Set(key, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	seen := map[string]struct{}{}
	out := make([]string, 0, 16)
	add := func(p string) {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range HardExclusions() {
		add(p)
	}
	if raw != "" {
		for _, p := range strings.Split(raw, ";") {
			add(p)
		}
	}
	return out
}

// migrateMarketScanDefaultsLocked upgrades legacy "skip almost everything" defaults
// to market-AV style Full/Quick coverage. Only rewrites when the value still matches
// the known legacy default so operator custom lists are preserved.
func (s *Store) migrateMarketScanDefaultsLocked() bool {
	if s.Values == nil {
		return false
	}
	changed := false
	norm := func(v string) string {
		v = strings.ToLower(strings.TrimSpace(v))
		v = strings.ReplaceAll(v, " ", "")
		return v
	}
	if cur, ok := s.Values[KeyExclusionPaths]; ok && norm(cur) == norm(LegacyExclusionPaths) {
		s.Values[KeyExclusionPaths] = DefaultExclusionPaths
		changed = true
	}
	if cur, ok := s.Values[KeyQuickScanPaths]; ok && norm(cur) == norm(LegacyQuickScanPaths) {
		s.Values[KeyQuickScanPaths] = DefaultQuickScanPaths
		changed = true
	}
	return changed
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

// MergeDefaultScanExtensions appends any missing DefaultScanExtensions entries
// so upgrades pick up new risky suffixes (e.g. .txt) without wiping custom lists.
// Returns true if the stored value changed.
func (s *Store) MergeDefaultScanExtensions() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mergeDefaultScanExtensionsLocked()
}

func (s *Store) mergeDefaultScanExtensionsLocked() bool {
	have := map[string]bool{}
	var ordered []string
	raw := ""
	if s.Values != nil {
		raw = s.Values[KeyScanExtensions]
	}
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if have[e] {
			continue
		}
		have[e] = true
		ordered = append(ordered, e)
	}
	changed := false
	for _, e := range strings.Split(DefaultScanExtensions, ",") {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" || have[e] {
			continue
		}
		have[e] = true
		ordered = append(ordered, e)
		changed = true
	}
	if !changed {
		return false
	}
	if s.Values == nil {
		s.Values = map[string]string{}
	}
	s.Values[KeyScanExtensions] = strings.Join(ordered, ",")
	return true
}

func (s *Store) QuickScanPaths() []string {
	raw := s.Get(KeyQuickScanPaths, "")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ";")
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}

	// When running as SYSTEM, expand user-scoped templates against each
	// interactive profile so Downloads/Desktop/Temp hit real user folders.
	profiles := quickScanProfileEnvs()
	for _, tmpl := range parts {
		tmpl = strings.TrimSpace(tmpl)
		if tmpl == "" {
			continue
		}
		if len(profiles) == 0 || !pathNeedsUserEnv(tmpl) {
			add(os.ExpandEnv(tmpl))
			continue
		}
		for _, env := range profiles {
			add(expandQuickPath(tmpl, env))
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
			if s.Values == nil {
				s.Values = map[string]string{}
			}
			s.Values[k] = v
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

