package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/quarantine"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/snapshot"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

type Manager struct {
	BaseDir    string
	Settings   *settings.Store
	Snapshot   *snapshot.Store
	API        *api.Client
	History    *history.Store
	Rules      *rules.Store
	Quarantine *quarantine.Store

	// OnScanIdle runs after a scan completes or is stopped (async, may be nil).
	OnScanIdle func()

	scanner *Scanner
	ssdeep  *ssdeepscan.Matcher

	mu          sync.Mutex
	running     atomic.Bool
	stopCh      chan struct{}
	scanAll     bool
	ruleCache   string
	rulePaths   []string
	ruleTempDir string

	statusMu sync.RWMutex
	status   StatusInfo
}

// EnsureRulesReady materializes YARA rules and returns an error if no rules are available.
// This is safe to call from request handlers to preflight scan readiness.
func (m *Manager) EnsureRulesReady() error {
	return m.ensureRules()
}

func (m *Manager) Status() StatusInfo {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	s := m.status
	s.Scanning = m.running.Load()
	return s
}

func (m *Manager) setStatus(fn func(*StatusInfo)) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	fn(&m.status)
}

func NewManager(baseDir string, st *settings.Store, snap *snapshot.Store, apiClient *api.Client, hist *history.Store, ruleStore *rules.Store, quar *quarantine.Store) *Manager {
	yaraPath := ResolveYaraPath(baseDir, st.Get(settings.KeyYaraEnginePath, ""))
	threshold := readSsdeepThreshold(st)
	return &Manager{
		BaseDir:    baseDir,
		Settings:   st,
		Snapshot:   snap,
		API:        apiClient,
		History:    hist,
		Rules:      ruleStore,
		Quarantine: quar,
		scanner:    NewScanner(yaraPath),
		ssdeep:     ssdeepscan.NewMatcher(baseDir, threshold),
	}
}

func readSsdeepThreshold(st *settings.Store) int {
	threshold := 85
	if st != nil {
		fmt.Sscanf(strings.TrimSpace(st.Get(settings.KeySsdeepThreshold, "85")), "%d", &threshold)
	}
	if threshold <= 0 {
		threshold = 85
	}
	return threshold
}

func (m *Manager) IsScanning() bool {
	return m.running.Load()
}

func (m *Manager) StartQuickScan()  { m.start(ScanQuick, "", false) }
func (m *Manager) StartFullScan()   { m.start(ScanFull, "", true) }
func (m *Manager) StartAutoScan()   { m.start(ScanAuto, "", true) }
func (m *Manager) StartSilentScan(path string) { m.start(ScanSilent, path, false) }

func (m *Manager) StartCustomScan(path string) {
	// Always force a full pass for user-picked paths (and short USB roots).
	// Incremental snapshot skip made CUSTOM SCAN look "stuck" (total>0, scanned=0).
	m.start(ScanCustom, path, true)
}

func (m *Manager) StopScan() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running.Load() && m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}
}

func (m *Manager) start(scanType ScanType, customPath string, scanAll bool) {
	m.mu.Lock()
	if m.running.Load() {
		m.mu.Unlock()
		return
	}
	m.running.Store(true)
	m.scanAll = scanAll
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	m.mu.Unlock()

	go m.scanWork(scanType, customPath, scanAll, stopCh)
}

func (m *Manager) scanWork(scanType ScanType, customPath string, scanAll bool, stopCh <-chan struct{}) {
	defer m.running.Store(false)

	result := Result{
		ScanType:     scanType,
		RulesVersion: m.Settings.Get(settings.KeyRulesVersion, "1.1"),
		StartTime:    time.Now(),
		ScanSource:   "Manual",
	}
	m.setStatus(func(s *StatusInfo) {
		*s = StatusInfo{Scanning: true, ScanType: string(scanType), Status: "running"}
	})
	if scanType == ScanCustom && len(strings.TrimSpace(customPath)) <= 3 {
		result.ScanSource = "USB"
	}

	_ = m.History.Append("scan.start", fmt.Sprintf("scan started: %s", scanType), map[string]any{
		"mode": APIMode(scanType, result.ScanSource),
	})

	if err := m.ensureRules(); err != nil {
		result.Status = "error"
		result.EndTime = time.Now()
		_ = m.History.Append("scan.error", "rules materialize: "+err.Error(), nil)
		return
	}

	m.mu.Lock()
	rulePaths := append([]string(nil), m.rulePaths...)
	m.mu.Unlock()

	m.sendScanLog(APIMode(scanType, result.ScanSource), scanStartDescription(m), "start")

	queue := NewQueue(queueCap)
	var totalFound, scanned, skipped, threats atomic.Int64
	stopped := func() bool {
		select {
		case <-stopCh:
			return true
		default:
			return false
		}
	}

	go func() {
		defer queue.Complete()
		enum := NewEnumerator(m.Settings, scanAll)
		enum.OnFile = func(item FileItem) {
			if stopped() {
				enum.Stop()
				return
			}
			totalFound.Add(1)
			m.setStatus(func(s *StatusInfo) {
				s.Total = int(totalFound.Load())
			})
			if !scanAll && scanType != ScanSilent {
				if rec, ok := m.Snapshot.Get(item.Path); ok {
					if !rec.NeedsRescan(item.Size, item.LastWriteUnix, result.RulesVersion) {
						skipped.Add(1)
						return
					}
				}
			}
			queue.Enqueue(item)
		}

		switch scanType {
		case ScanQuick:
			enum.EnumerateQuick()
		case ScanCustom:
			enum.EnumeratePath(customPath)
		case ScanSilent:
			if customPath != "" {
				if st, err := os.Stat(customPath); err == nil && !st.IsDir() {
					totalFound.Add(1)
					queue.Enqueue(FileItem{
						Path:          customPath,
						Size:          st.Size(),
						LastWriteUnix: st.ModTime().Unix(),
						CreateUnix:    st.ModTime().Unix(),
					})
				}
			}
		default:
			enum.EnumerateAllFixedDrives()
		}
	}()

	active := atomic.Int32{}
	for !stopped() {
		batch, ok := queue.DequeueBatch(batchSize)
		if !ok {
			break
		}
		for active.Load() >= scanWorkers {
			time.Sleep(20 * time.Millisecond)
			if stopped() {
				break
			}
		}
		active.Add(1)
		b := batch
		go func() {
			defer active.Add(-1)
			m.processBatch(b, rulePaths, &result, scanType, &scanned, &threats, stopped)
		}()
	}
	for active.Load() > 0 {
		time.Sleep(50 * time.Millisecond)
	}

	result.TotalFound = int(totalFound.Load())
	result.FilesScanned = int(scanned.Load())
	result.FilesSkipped = int(skipped.Load())
	result.ThreatsFound = int(threats.Load())
	result.EndTime = time.Now()
	if stopped() {
		result.Status = "stopped"
	} else {
		result.Status = "completed"
	}
	m.setStatus(func(s *StatusInfo) {
		s.Scanning = false
		s.Scanned = int(scanned.Load())
		s.Skipped = int(skipped.Load())
		s.Total = int(totalFound.Load())
		s.Threats = int(threats.Load())
		s.Status = result.Status
	})

	_ = m.Snapshot.Save()
	_ = m.History.Append("scan.end", fmt.Sprintf(
		"scan %s: scanned=%d skipped=%d total=%d threats=%d",
		result.Status, result.FilesScanned, result.FilesSkipped, result.TotalFound, result.ThreatsFound), map[string]any{
		"scanned": result.FilesScanned,
		"skipped": result.FilesSkipped,
		"total":   result.TotalFound,
		"threats": result.ThreatsFound,
		"yara":    countThreatsByEngine(result.Threats, "yara"),
		"ssdeep":  countThreatsByEngine(result.Threats, "ssdeep"),
	})
	_ = m.History.Append("ui.notify", fmt.Sprintf(
		"Scan %s — scanned %d, skipped %d, threats %d",
		result.Status, result.FilesScanned, result.FilesSkipped, result.ThreatsFound), map[string]any{
		"kind":    "scan",
		"scanned": result.FilesScanned,
		"skipped": result.FilesSkipped,
		"threats": result.ThreatsFound,
	})

	yaraN := countThreatsByEngine(result.Threats, "yara")
	ssdeepN := countThreatsByEngine(result.Threats, "ssdeep")
	desc := fmt.Sprintf("Scan %s: scanned=%d skipped=%d total=%d threats=%d (yara=%d ssdeep=%d)",
		result.Status, result.FilesScanned, result.FilesSkipped, result.TotalFound, result.ThreatsFound, yaraN, ssdeepN)
	m.sendScanLog(APIMode(scanType, result.ScanSource), desc, "end")

	if m.OnScanIdle != nil {
		cb := m.OnScanIdle
		go cb()
	}
}

func countThreatsByEngine(threats []Threat, engine string) int {
	n := 0
	for _, th := range threats {
		e := th.Engine
		if e == "" {
			e = "yara"
		}
		if e == engine {
			n++
		}
	}
	return n
}

func (m *Manager) processBatch(batch []FileItem, rulePaths []string, result *Result, scanType ScanType, scanned, threats *atomic.Int64, stopped func() bool) {
	if len(batch) == 0 || stopped() {
		return
	}
	if m.ssdeep != nil {
		m.ssdeep.SetThreshold(readSsdeepThreshold(m.Settings))
	}
	paths := make([]string, len(batch))
	sizes := make(map[string]int64, len(batch))
	for i, item := range batch {
		paths[i] = item.Path
		sizes[item.Path] = item.Size
	}

	matches, err := m.scanner.ScanBatch(rulePaths, paths)
	if err != nil {
		_ = m.History.Append("scan.error", "yara batch: "+err.Error(), nil)
		return
	}

	matchMap := map[string][]string{}
	for _, match := range matches {
		key := strings.ToLower(match.FilePath)
		matchMap[key] = append(matchMap[key], match.Rule)
	}

	// YARA-first: only miss files go to ssdeep (enabled by default).
	var cleanPaths []string
	for _, item := range batch {
		if _, hit := matchMap[strings.ToLower(item.Path)]; !hit {
			cleanPaths = append(cleanPaths, item.Path)
		}
	}
	ssdeepHits := map[string]ssdeepscan.Match{}
	if m.ssdeepEnabled() && len(cleanPaths) > 0 && m.ssdeep != nil {
		hits, serr := m.ssdeep.ScanCleanFiles(cleanPaths, sizes, stopped)
		if serr != nil {
			_ = m.History.Append("scan.error", "ssdeep batch: "+serr.Error(), nil)
		} else {
			for _, h := range hits {
				ssdeepHits[strings.ToLower(h.Path)] = h
			}
		}
	}

	var batchThreats []Threat
	now := time.Now()
	for _, item := range batch {
		if stopped() {
			return
		}
		key := strings.ToLower(item.Path)
		rulesMatched, infected := matchMap[key]
		status := "clean"
		if infected {
			status = "infected"
			threats.Add(1)
			for _, rule := range rulesMatched {
				th := Threat{Path: item.Path, Rule: rule, ScanType: scanType, Engine: "yara"}
				result.Threats = append(result.Threats, th)
				batchThreats = append(batchThreats, th)
			}
		} else if hit, ok := ssdeepHits[key]; ok {
			// Second pass only: YARA clean + ssdeep hit → still one file / one threat count.
			status = "infected"
			threats.Add(1)
			th := Threat{
				Path:     item.Path,
				Rule:     ssdeepscan.RuleLabelWithFamily(hit.Name, hit.Family, hit.Score),
				ScanType: scanType,
				Engine:   "ssdeep",
				Score:    hit.Score,
				Ssdeep:   hit.Ssdeep,
			}
			result.Threats = append(result.Threats, th)
			batchThreats = append(batchThreats, th)
		}

		m.Snapshot.Upsert(item.Path, snapshot.FileRecord{
			Size:           item.Size,
			LastWriteUnix:  item.LastWriteUnix,
			CreateUnix:     item.CreateUnix,
			RulesVersion:   result.RulesVersion,
			LastScanResult: status,
			LastScanUnix:   now.Unix(),
		})
		scannedCount := scanned.Add(1)
		m.setStatus(func(s *StatusInfo) {
			s.Scanned = int(scannedCount)
			s.Threats = int(threats.Load())
		})
		if scannedCount%3 == 1 || status == "infected" {
			_ = m.History.Append("scan.item", "Scanning: "+filepath.Base(item.Path), map[string]any{"path": item.Path})
		}
	}

	if len(batchThreats) > 0 {
		m.reportThreats(batchThreats)
		seen := map[string]bool{}
		for _, th := range batchThreats {
			key := strings.ToLower(th.Path)
			if seen[key] {
				continue
			}
			seen[key] = true
			if m.shouldQuarantine() && m.Quarantine != nil {
				_ = m.Quarantine.Isolate(th.Path, th.Rule)
			}
		}
	}
}

func (m *Manager) ssdeepEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(m.Settings.Get(settings.KeySsdeepEnabled, "true")))
	return v == "true" || v == "1" || v == "yes"
}

func (m *Manager) ssdeepReportAPIEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(m.Settings.Get(settings.KeySsdeepReportAPI, "true")))
	return v == "true" || v == "1" || v == "yes"
}

func (m *Manager) shouldQuarantine() bool {
	v := strings.ToLower(strings.TrimSpace(m.Settings.Get(settings.KeyQuarantineOnDetect, "true")))
	return v == "true" || v == "1" || v == "yes"
}

func (m *Manager) shouldSendSsdeepCandidate() bool {
	v := strings.ToLower(strings.TrimSpace(m.Settings.Get(settings.KeySendSsdeepCandidate, "false")))
	return v == "true" || v == "1" || v == "yes"
}

func scanStartDescription(m *Manager) string {
	engines := "yara"
	if m.ssdeepEnabled() {
		engines = "yara+ssdeep"
	}
	return fmt.Sprintf("Scan started; engines=%s", engines)
}

func (m *Manager) reportThreats(threats []Threat) {
	if m.API == nil {
		return
	}
	agentID := m.agentID()
	device := sysinfo.Hostname()
	ts := time.Now().Format("2006-01-02 15:04:05")

	fuzzyFor := func(th Threat) string {
		if s := strings.TrimSpace(th.Ssdeep); s != "" {
			return s
		}
		return ssdeepscan.FuzzyHashFile(th.Path)
	}

	// Legacy web: YARA detections only (unchanged payload).
	yaraItems := make([]api.YaraLogItem, 0, len(threats))
	for _, th := range threats {
		if th.Engine == "ssdeep" {
			continue
		}
		yaraItems = append(yaraItems, api.YaraLogItem{
			AgentID:     agentID,
			Path:        th.Path,
			Rule:        th.Rule,
			Description: "Malware detected: " + th.Rule,
			DeviceName:  device,
			FileText:    "",
			FirstScan:   ts,
			LastScan:    ts,
		})
	}
	if len(yaraItems) > 0 {
		if _, _, err := m.API.SendLogYara(yaraItems); err != nil {
			_ = m.History.Append("api.error", "sendLogYara: "+err.Error(), nil)
		} else {
			_ = m.History.Append("api.ok", fmt.Sprintf("sendLogYara (%d threats)", len(yaraItems)), nil)
		}
	}

	seen := map[string]bool{}
	hashItems := make([]api.HashItem, 0)
	for _, th := range threats {
		if th.Engine == "ssdeep" {
			continue
		}
		if seen[strings.ToLower(th.Path)] {
			continue
		}
		seen[strings.ToLower(th.Path)] = true
		md5 := FileMD5(th.Path)
		if md5 == "" {
			continue
		}
		hashItems = append(hashItems, api.HashItem{
			FileName: filepath.Base(th.Path),
			HashMD5:  md5,
			Path:     th.Path,
		})
	}
	if len(hashItems) > 0 {
		if _, _, err := m.API.SendHash(hashItems); err != nil {
			_ = m.History.Append("api.error", "sendHash: "+err.Error(), nil)
		}
	}

	// New endpoint: fuzzy hash + engine metadata (YARA and ssdeep); web implements when ready.
	if !m.ssdeepReportAPIEnabled() {
		return
	}
	ssdeepItems := make([]api.SsdeepLogItem, 0, len(threats))
	for _, th := range threats {
		fuzzy := fuzzyFor(th)
		if fuzzy == "" {
			continue
		}
		engine := th.Engine
		if engine == "" {
			engine = "yara"
		}
		desc := "Malware detected: " + th.Rule
		if engine == "ssdeep" {
			desc = fmt.Sprintf("Ssdeep similarity match: %s (score=%d)", th.Rule, th.Score)
		}
		item := api.SsdeepLogItem{
			AgentID:     agentID,
			Path:        th.Path,
			FileName:    filepath.Base(th.Path),
			HashMD5:     FileMD5(th.Path),
			Ssdeep:      fuzzy,
			Engine:      engine,
			Rule:        th.Rule,
			Description: desc,
			DeviceName:  device,
			DetectedAt:  ts,
		}
		if engine == "ssdeep" {
			item.Score = th.Score
		}
		ssdeepItems = append(ssdeepItems, item)
	}
	if len(ssdeepItems) > 0 {
		if _, _, err := m.API.SendLogSsdeep(ssdeepItems); err != nil {
			_ = m.History.Append("api.error", "sendLogSsdeep: "+err.Error(), nil)
		} else {
			_ = m.History.Append("api.ok", fmt.Sprintf("sendLogSsdeep (%d)", len(ssdeepItems)), nil)
		}
	}

	if !m.shouldSendSsdeepCandidate() {
		return
	}
	candidates := make([]api.SsdeepCandidateItem, 0, len(threats))
	for _, th := range threats {
		fuzzy := fuzzyFor(th)
		if fuzzy == "" {
			continue
		}
		engine := th.Engine
		if engine == "" {
			engine = "yara"
		}
		candidate := api.SsdeepCandidateItem{
			AgentID:    agentID,
			Path:       th.Path,
			FileName:   filepath.Base(th.Path),
			HashMD5:    FileMD5(th.Path),
			HashSHA256: FileSHA256(th.Path),
			Ssdeep:     fuzzy,
			Engine:     engine,
			Rule:       th.Rule,
			DetectedAt: ts,
			ScanMode:   APIMode(th.ScanType, ""),
			Source:     "agent_detection",
		}
		if engine == "ssdeep" {
			candidate.Score = th.Score
			candidate.Source = "ssdeep_hit"
		} else {
			candidate.Source = "yara_hit"
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) > 0 {
		if _, _, err := m.API.SendSsdeepCandidate(candidates); err != nil {
			_ = m.History.Append("api.error", "sendSsdeepCandidate: "+err.Error(), nil)
		} else {
			_ = m.History.Append("api.ok", fmt.Sprintf("sendSsdeepCandidate (%d)", len(candidates)), nil)
		}
	}
}

func (m *Manager) sendScanLog(mode, desc, typ string) {
	if m.API == nil {
		return
	}
	_, _, _ = m.API.SendAgentScanLog([]api.ScanLogItem{{
		AgentID:     m.agentID(),
		Description: desc,
		TimeStamp:   time.Now().Format("2006-01-02 15:04:05"),
		Mode:        mode,
		Type:        typ,
	}})
}

func (m *Manager) agentID() int64 {
	s := strings.TrimSpace(m.Settings.Get("agent_id", "0"))
	var id int64
	fmt.Sscanf(s, "%d", &id)
	return id
}

func (m *Manager) ensureRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	version := m.Settings.Get(settings.KeyRulesVersion, "")
	if version != "" && version == m.ruleCache && len(m.rulePaths) > 0 {
		if _, err := os.Stat(m.rulePaths[0]); err == nil {
			return nil
		}
	}
	if m.ruleTempDir != "" {
		_ = rules.WipeMaterializedDir(m.ruleTempDir)
		m.ruleTempDir = ""
		m.rulePaths = nil
	}

	tempDir, err := os.MkdirTemp("", "insite_rules_*")
	if err != nil {
		return err
	}
	entries, err := m.Rules.Materialize(tempDir)
	if err != nil {
		_ = rules.WipeMaterializedDir(tempDir)
		return err
	}
	if len(entries) == 0 {
		_ = rules.WipeMaterializedDir(tempDir)
		return fmt.Errorf("no rule entry files materialized")
	}
	m.rulePaths = entries
	m.ruleTempDir = tempDir
	m.ruleCache = version
	return nil
}

// RefreshRules clears cached materialized rules (call after rule sync).
func (m *Manager) RefreshRules() {
	m.mu.Lock()
	tmp := m.ruleTempDir
	m.ruleTempDir = ""
	m.rulePaths = nil
	m.ruleCache = ""
	m.mu.Unlock()
	if tmp != "" {
		_ = rules.WipeMaterializedDir(tmp)
	}
}

func (m *Manager) RefreshSsdeep() {
	if m == nil || m.ssdeep == nil {
		return
	}
	m.ssdeep.SetThreshold(readSsdeepThreshold(m.Settings))
	m.ssdeep.Reload()
}
