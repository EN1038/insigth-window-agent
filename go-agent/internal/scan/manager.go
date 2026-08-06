package scan

import (
	"crypto/rand"
	"encoding/hex"
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
	"github.com/sosecure/insite-agent/internal/reportq"
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
	ReportQ    *reportq.Queue

	// OnScanIdle runs after a scan completes or is stopped (async, may be nil).
	OnScanIdle func()

	scanner *Scanner
	ssdeep  *ssdeepscan.Matcher

	mu            sync.Mutex
	running       atomic.Bool
	stopCh        chan struct{}
	scanAll       bool
	ruleCache     string
	rulePaths     []string
	ruleTempDir   string
	pendingSilent []string

	statusMu sync.RWMutex
	status   StatusInfo

	// Realtime (silent) session totals — accumulate across file events until a
	// FULL / QUICK / CUSTOM / AUTO on-demand scan starts (then reset to 0).
	rtSessionMu      sync.Mutex
	rtSessionScanned int
	rtSessionThreats int
	rtBaseScanned    atomic.Int64 // committed session offset while a silent scan runs
	rtBaseThreats    atomic.Int64
	rtAccumulating   atomic.Bool  // status Total includes pending silent queue
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

func (m *Manager) resetRealtimeSession() {
	m.rtSessionMu.Lock()
	m.rtSessionScanned = 0
	m.rtSessionThreats = 0
	m.rtSessionMu.Unlock()
	m.rtBaseScanned.Store(0)
	m.rtBaseThreats.Store(0)
	m.rtAccumulating.Store(false)
}

func (m *Manager) realtimeSession() (scanned, threats int) {
	m.rtSessionMu.Lock()
	defer m.rtSessionMu.Unlock()
	return m.rtSessionScanned, m.rtSessionThreats
}

func (m *Manager) commitRealtimeSession(scanned, threats int) {
	if scanned <= 0 && threats <= 0 {
		return
	}
	m.rtSessionMu.Lock()
	m.rtSessionScanned += scanned
	m.rtSessionThreats += threats
	m.rtSessionMu.Unlock()
}

func (m *Manager) pendingSilentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendingSilent)
}

// paintCounts writes overview counters. During realtime, values are session
// totals (prior silent files + this file) and Total includes the silent queue.
func (m *Manager) paintCounts(s *StatusInfo, scanned, total, threats int) {
	baseS := int(m.rtBaseScanned.Load())
	baseT := int(m.rtBaseThreats.Load())
	s.Scanned = baseS + scanned
	s.Threats = baseT + threats
	extra := 0
	if m.rtAccumulating.Load() {
		extra = m.pendingSilentCount()
	}
	s.Total = baseS + total + extra
}

func NewManager(baseDir string, st *settings.Store, snap *snapshot.Store, apiClient *api.Client, hist *history.Store, ruleStore *rules.Store, quar *quarantine.Store, rq *reportq.Queue) *Manager {
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
		ReportQ:    rq,
		scanner:    NewScannerFromSettings(yaraPath, st),
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

const maxPendingSilent = 200

// Start* methods return false when a scan is already running (except silent,
// which is queued). Callers must not assume work started on a false return.

func (m *Manager) StartQuickScan() bool {
	// Always force a full pass for quick paths. Snapshot skip made QUICK SCAN
	// finish immediately (scanned=0) when files were previously scanned.
	return m.start(ScanQuick, "", true, SourceManual)
}

func (m *Manager) StartScheduledQuickScan() bool {
	return m.start(ScanQuick, "", true, SourceSchedule)
}

func (m *Manager) StartLoginQuickScan() bool {
	return m.start(ScanQuick, "", true, SourceLogin)
}

func (m *Manager) StartFullScan() bool { return m.start(ScanFull, "", true, SourceManual) }
func (m *Manager) StartAutoScan() bool { return m.start(ScanAuto, "", true, SourceManual) }

func (m *Manager) StartSilentScan(path string) bool {
	return m.start(ScanSilent, path, false, SourceRealtime)
}

func (m *Manager) StartCustomScan(path string) bool {
	// Always force a full pass for user-picked paths (and short USB roots).
	// Incremental snapshot skip made CUSTOM SCAN look "stuck" (total>0, scanned=0).
	source := SourceManual
	if len(strings.TrimSpace(path)) <= 3 {
		source = SourceUSB
	}
	return m.start(ScanCustom, path, true, source)
}

func (m *Manager) StopScan() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running.Load() && m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}
}

func (m *Manager) start(scanType ScanType, customPath string, scanAll bool, source string) bool {
	m.mu.Lock()
	if m.running.Load() {
		if scanType == ScanSilent && strings.TrimSpace(customPath) != "" {
			m.enqueueSilentLocked(customPath)
		}
		m.mu.Unlock()
		return false
	}
	// On-demand scans start a fresh overview session; drop queued realtime files.
	if scanType != ScanSilent {
		m.pendingSilent = nil
		m.resetRealtimeSession()
	}
	m.running.Store(true)
	m.scanAll = scanAll
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	m.mu.Unlock()

	go m.scanWork(scanType, customPath, scanAll, source, stopCh)
	return true
}

func (m *Manager) enqueueSilentLocked(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	key := strings.ToLower(path)
	for _, p := range m.pendingSilent {
		if strings.ToLower(p) == key {
			return
		}
	}
	if len(m.pendingSilent) >= maxPendingSilent {
		m.pendingSilent = m.pendingSilent[1:]
	}
	m.pendingSilent = append(m.pendingSilent, path)
}

func (m *Manager) drainSilentQueue() {
	m.mu.Lock()
	if len(m.pendingSilent) == 0 {
		m.mu.Unlock()
		return
	}
	path := m.pendingSilent[0]
	m.pendingSilent = m.pendingSilent[1:]
	m.mu.Unlock()
	_ = m.StartSilentScan(path)
}

func (m *Manager) scanWork(scanType ScanType, customPath string, scanAll bool, source string, stopCh <-chan struct{}) {
	defer func() {
		m.running.Store(false)
		m.drainSilentQueue()
		if m.OnScanIdle != nil {
			cb := m.OnScanIdle
			go cb()
		}
	}()

	if source == "" {
		source = SourceManual
	}
	result := Result{
		ScanType:     scanType,
		RulesVersion: m.Settings.Get(settings.KeyRulesVersion, "1.1"),
		StartTime:    time.Now(),
		ScanSource:   source,
	}
	verbose := scanType != ScanSilent
	phaseMsg := fmt.Sprintf("Starting %s scan…", scanType)
	discoveryDoneAtStart := scanType == ScanSilent
	if scanType == ScanSilent {
		sc, th := m.realtimeSession()
		m.rtBaseScanned.Store(int64(sc))
		m.rtBaseThreats.Store(int64(th))
		m.rtAccumulating.Store(true)
	} else {
		m.rtBaseScanned.Store(0)
		m.rtBaseThreats.Store(0)
		m.rtAccumulating.Store(false)
	}
	m.setStatus(func(s *StatusInfo) {
		*s = StatusInfo{
			Scanning:      true,
			ScanType:      string(scanType),
			Source:        source,
			Status:        "discovering",
			Message:       phaseMsg,
			CurrentEngine: "discover",
			DiscoveryDone: discoveryDoneAtStart,
		}
		if discoveryDoneAtStart {
			s.Status = "scanning"
			s.CurrentEngine = ""
		}
		m.paintCounts(s, 0, 0, 0)
	})
	if scanType == ScanCustom && source != SourceUSB && len(strings.TrimSpace(customPath)) <= 3 {
		result.ScanSource = SourceUSB
		source = SourceUSB
		m.setStatus(func(s *StatusInfo) { s.Source = source })
	}

	_ = m.History.Append("scan.start", fmt.Sprintf("scan started: %s", scanType), map[string]any{
		"mode":   APIMode(scanType, source),
		"source": source,
	})
	if verbose {
		_ = m.History.Append("scan.progress", phaseMsg, nil)
	}

	if err := m.ensureRules(); err != nil {
		result.Status = "error"
		result.EndTime = time.Now()
		m.setStatus(func(s *StatusInfo) {
			s.Scanning = false
			s.Status = "error"
			s.Message = "Rules not ready: " + err.Error()
		})
		_ = m.History.Append("scan.error", "rules materialize: "+err.Error(), nil)
		return
	}

	m.mu.Lock()
	rulePaths := append([]string(nil), m.rulePaths...)
	m.mu.Unlock()

	runID := newScanRunID()
	if verbose {
		m.setStatus(func(s *StatusInfo) {
			s.Status = "discovering"
			s.Message = "Notifying Center…"
		})
	}
	m.sendScanLog(APIMode(scanType, source), scanStartDescription(m), "start", runID)

	queue := NewQueue(queueCap)
	var totalFound, scanned, skipped, threats atomic.Int64
	var lastProgressLog, lastStatusTick atomic.Int64
	lastProgressLog.Store(time.Now().UnixNano())
	lastStatusTick.Store(time.Now().UnixNano())
	const statusTick = int64(150 * time.Millisecond)
	const progressTick = int64(1200 * time.Millisecond)
	publishDiscover := func(pathOrDir string, force bool) {
		if !verbose {
			return
		}
		n := totalFound.Load()
		sc := scanned.Load()
		nowNano := time.Now().UnixNano()
		prev := lastStatusTick.Load()
		if !force && nowNano-prev < statusTick {
			return
		}
		if !lastStatusTick.CompareAndSwap(prev, nowNano) && !force {
			return
		}
		skipN := int(skipped.Load())
		base := filepath.Base(pathOrDir)
		m.setStatus(func(s *StatusInfo) {
			m.paintCounts(s, int(sc), int(n), int(threats.Load()))
			s.Skipped = skipN
			s.DiscoveryDone = false
			// Keep status as discovering until enumerator finishes so UI does not
			// treat Scanned/Total as overall percent while Total is still growing.
			s.Status = "discovering"
			s.CurrentEngine = "discover"
			s.CurrentPath = pathOrDir
			if base != "" && base != "." {
				s.CurrentFile = base
			}
			if sc > 0 {
				s.Message = fmt.Sprintf("Discovering… found %d · scanned %d", s.Total, s.Scanned)
			} else {
				s.Message = fmt.Sprintf("Discovering files… %d found", s.Total)
			}
		})
	}
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
		// Full/Auto ignore extension filters so the pass is not artificially narrow.
		allExt := scanType == ScanFull || scanType == ScanAuto
		enum := NewEnumerator(m.Settings, scanAll, allExt)
		enum.OnDirectory = func(dir string) {
			if stopped() {
				return
			}
			publishDiscover(dir, false)
		}
		enum.OnFile = func(item FileItem) {
			if stopped() {
				enum.Stop()
				return
			}
			n := totalFound.Add(1)
			publishDiscover(item.Path, n == 1)
			nowNano := time.Now().UnixNano()
			prev := lastProgressLog.Load()
			if verbose && (n == 1 || nowNano-prev > progressTick) && lastProgressLog.CompareAndSwap(prev, nowNano) {
				_ = m.History.Append("scan.progress", fmt.Sprintf("Discovering… %d found — %s", n, item.Path), map[string]any{
					"total":  n,
					"path":   item.Path,
					"engine": "discover",
				})
			}
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
		if verbose {
			n := totalFound.Load()
			sc := scanned.Load()
			m.setStatus(func(s *StatusInfo) {
				s.DiscoveryDone = true
				s.Status = "scanning"
				m.paintCounts(s, int(sc), int(n), int(threats.Load()))
				s.Skipped = int(skipped.Load())
				s.Message = fmt.Sprintf("Scanning… %d / %d", s.Scanned, s.Total)
				if s.CurrentEngine == "discover" {
					s.CurrentEngine = ""
				}
			})
			_ = m.History.Append("scan.progress", fmt.Sprintf("Discovery done — scanning %d files", n), map[string]any{
				"total": n,
			})
		} else {
			m.setStatus(func(s *StatusInfo) {
				s.DiscoveryDone = true
				s.Status = "scanning"
				m.paintCounts(s, int(scanned.Load()), int(totalFound.Load()), int(threats.Load()))
			})
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
			m.processBatch(b, rulePaths, &result, scanType, &scanned, &totalFound, &threats, stopped)
			if yaraFileDelay > 0 && !stopped() {
				time.Sleep(yaraFileDelay)
			}
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
	if scanType == ScanSilent {
		m.commitRealtimeSession(result.FilesScanned, result.ThreatsFound)
		// Bases catch up to committed session so idle/final status stays cumulative.
		sc, th := m.realtimeSession()
		m.rtBaseScanned.Store(int64(sc))
		m.rtBaseThreats.Store(int64(th))
	}
	m.setStatus(func(s *StatusInfo) {
		s.Scanning = true
		s.DiscoveryDone = true
		if scanType == ScanSilent {
			m.paintCounts(s, 0, 0, 0)
		} else {
			m.paintCounts(s, int(scanned.Load()), int(totalFound.Load()), int(threats.Load()))
		}
		s.Skipped = int(skipped.Load())
		s.Status = "finalizing"
		s.Message = "Saving results…"
		s.CurrentFile = ""
		s.CurrentPath = ""
		s.CurrentEngine = ""
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
		"source":  source,
	})
	// Realtime clean hits would spam mailbox/toasts; only notify when threats
	// found or the scan was an on-demand / scheduled pass.
	if scanType != ScanSilent || result.ThreatsFound > 0 {
		_ = m.History.Append("ui.notify", formatScanUserMessage(result.Status, result.FilesScanned, result.FilesSkipped, result.ThreatsFound), map[string]any{
			"kind":    "scan",
			"scanned": result.FilesScanned,
			"skipped": result.FilesSkipped,
			"threats": result.ThreatsFound,
		})
	}

	yaraN := countThreatsByEngine(result.Threats, "yara")
	ssdeepN := countThreatsByEngine(result.Threats, "ssdeep")
	desc := fmt.Sprintf("Scan %s: scanned=%d skipped=%d total=%d threats=%d (yara=%d ssdeep=%d)",
		result.Status, result.FilesScanned, result.FilesSkipped, result.TotalFound, result.ThreatsFound, yaraN, ssdeepN)
	m.setStatus(func(s *StatusInfo) {
		s.Status = "finalizing"
		s.Message = "Updating Center…"
	})
	m.sendScanLog(APIMode(scanType, source), desc, "end", runID)

	m.setStatus(func(s *StatusInfo) {
		s.Scanning = false
		s.DiscoveryDone = true
		if scanType == ScanSilent {
			m.paintCounts(s, 0, 0, 0)
		} else {
			m.paintCounts(s, result.FilesScanned, result.TotalFound, result.ThreatsFound)
		}
		s.Skipped = result.FilesSkipped
		s.Status = result.Status
		s.Message = formatScanUserMessage(result.Status, result.FilesScanned, result.FilesSkipped, result.ThreatsFound)
		s.CurrentFile = ""
		s.CurrentPath = ""
		s.CurrentEngine = ""
	})
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

func (m *Manager) processBatch(batch []FileItem, rulePaths []string, result *Result, scanType ScanType, scanned, totalFound, threats *atomic.Int64, stopped func() bool) {
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

	already := int(scanned.Load())
	totalHint := int(totalFound.Load())
	m.setStatus(func(s *StatusInfo) {
		if s.DiscoveryDone {
			s.Status = "scanning"
		} else {
			s.Status = "discovering"
		}
		m.paintCounts(s, already, totalHint, int(threats.Load()))
		s.CurrentEngine = "yara"
		s.CurrentPath = paths[0]
		s.CurrentFile = filepath.Base(paths[0])
		s.Message = fmt.Sprintf("Analyzing with YARA… %d files", len(paths))
	})
	stopPulse := m.pulseStatus(func(elapsed time.Duration) {
		m.setStatus(func(s *StatusInfo) {
			if s.DiscoveryDone {
				s.Status = "scanning"
			} else {
				s.Status = "discovering"
			}
			s.CurrentEngine = "yara"
			s.Message = fmt.Sprintf("Analyzing with YARA… %d files (%ds)", len(paths), int(elapsed.Seconds()))
		})
	}, 500*time.Millisecond)

	matches, err := m.scanner.ScanBatch(rulePaths, paths)
	stopPulse()
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
		m.setStatus(func(s *StatusInfo) {
			if s.DiscoveryDone {
				s.Status = "scanning"
			} else {
				s.Status = "discovering"
			}
			s.CurrentEngine = "ssdeep"
			s.CurrentPath = cleanPaths[0]
			s.CurrentFile = filepath.Base(cleanPaths[0])
			s.Message = fmt.Sprintf("Fuzzy hashing… 0 / %d", len(cleanPaths))
		})
		hits, serr := m.ssdeep.ScanCleanFiles(cleanPaths, sizes, stopped, func(done int, path string) {
			m.setStatus(func(s *StatusInfo) {
				if s.DiscoveryDone {
					s.Status = "scanning"
				} else {
					s.Status = "discovering"
				}
				s.CurrentEngine = "ssdeep"
				s.CurrentPath = path
				s.CurrentFile = filepath.Base(path)
				s.Message = fmt.Sprintf("Fuzzy hashing… %d / %d", done, len(cleanPaths))
			})
		})
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
			// Second pass only: YARA clean + ssdeep hit â†’ still one file / one threat count.
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
		totalN := int(totalFound.Load())
		threatN := int(threats.Load())
		engineLabel := "yara"
		if infected {
			engineLabel = "yara"
		} else if _, ok := ssdeepHits[key]; ok {
			engineLabel = "ssdeep"
		}
		m.setStatus(func(s *StatusInfo) {
			if s.DiscoveryDone {
				s.Status = "scanning"
			} else {
				s.Status = "discovering"
			}
			m.paintCounts(s, int(scannedCount), totalN, threatN)
			s.CurrentPath = item.Path
			s.CurrentFile = filepath.Base(item.Path)
			s.CurrentEngine = engineLabel
			if s.DiscoveryDone {
				s.Message = fmt.Sprintf("Scanning… %d / %d", s.Scanned, s.Total)
			} else {
				s.Message = fmt.Sprintf("Discovering… found %d · scanned %d", s.Total, s.Scanned)
			}
		})
		// Prefer status updates for live UX; history is sparse (encrypted I/O).
		if status == "infected" || scannedCount == 1 || scannedCount%40 == 0 {
			_ = m.History.Append("scan.item", fmt.Sprintf("%s  %s", strings.ToUpper(engineLabel), item.Path), map[string]any{
				"path":    item.Path,
				"engine":  engineLabel,
				"scanned": scannedCount,
				"total":   totalN,
			})
		}
	}

	if len(batchThreats) > 0 {
		uniq := uniqueThreatPaths(batchThreats)
		m.setStatus(func(s *StatusInfo) {
			s.Status = "finalizing"
			s.Message = fmt.Sprintf("Reporting %d detections…", len(uniq))
			s.CurrentFile = ""
		})
		_ = m.History.Append("scan.progress", fmt.Sprintf("Reporting %d detections…", len(uniq)), nil)
		stopPulse := m.pulseStatus(func(elapsed time.Duration) {
			m.setStatus(func(s *StatusInfo) {
				s.Status = "finalizing"
				s.Message = fmt.Sprintf("Reporting %d detections… (%ds)", len(uniq), int(elapsed.Seconds()))
			})
		}, 500*time.Millisecond)
		m.reportThreats(batchThreats)
		stopPulse()

		if m.shouldQuarantine() && m.Quarantine != nil {
			for i, th := range uniq {
				if stopped() {
					return
				}
				m.setStatus(func(s *StatusInfo) {
					s.Status = "finalizing"
					s.Message = fmt.Sprintf("Quarantining… %d / %d", i+1, len(uniq))
					s.CurrentPath = th.Path
					s.CurrentFile = filepath.Base(th.Path)
					s.CurrentEngine = ""
				})
				_ = m.Quarantine.Isolate(th.Path, th.Rule)
			}
		}
	}
}

// pulseStatus calls tick on an interval until the returned stop func is called.
func (m *Manager) pulseStatus(tick func(elapsed time.Duration), every time.Duration) func() {
	if every <= 0 {
		every = 500 * time.Millisecond
	}
	done := make(chan struct{})
	start := time.Now()
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				tick(now.Sub(start))
			}
		}
	}()
	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}
}

func uniqueThreatPaths(threats []Threat) []Threat {
	seen := map[string]bool{}
	out := make([]Threat, 0, len(threats))
	for _, th := range threats {
		key := strings.ToLower(th.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, th)
	}
	return out
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
	agentID := m.agentID()
	if agentID <= 0 {
		// Center matches detections by agent_id; 0 means rows land orphaned and
		// never show under Alert / Scan History.
		_ = m.History.Append("api.warn", "agent_id=0 — detections may not appear on Center; re-approve or Sync now", nil)
	}
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
		if m.API == nil {
			_ = m.enqueueReport(reportq.KindYara, yaraItems)
			_ = m.History.Append("api.warn", fmt.Sprintf("sendLogYara queued (%d threats); Center API not linked yet", len(yaraItems)), nil)
		} else if resp, _, err := m.API.SendLogYara(yaraItems); !reportOK(resp, err) {
			_ = m.History.Append("api.error", "sendLogYara: "+errString(err, resp), nil)
			_ = m.enqueueReport(reportq.KindYara, yaraItems)
		} else {
			_ = m.History.Append("api.ok", fmt.Sprintf("sendLogYara (%d threats, agent_id=%d)", len(yaraItems), agentID), map[string]any{
				"agent_id": agentID, "count": len(yaraItems),
			})
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
			Hash:     md5,
			Type:     api.HashTypeMD5,
			Path:     th.Path,
			FileName: filepath.Base(th.Path),
		})
	}
	if len(hashItems) > 0 {
		if m.API == nil {
			_ = m.enqueueReport(reportq.KindHash, hashItems)
		} else if resp, _, err := m.API.SendHash(hashItems); !reportOK(resp, err) {
			_ = m.History.Append("api.error", "sendHash: "+errString(err, resp), nil)
			_ = m.enqueueReport(reportq.KindHash, hashItems)
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
		if m.API == nil {
			_ = m.enqueueReport(reportq.KindSsdeep, ssdeepItems)
		} else if resp, _, err := m.API.SendLogSsdeep(ssdeepItems); !reportOK(resp, err) {
			_ = m.History.Append("api.error", "sendLogSsdeep: "+errString(err, resp), nil)
			_ = m.enqueueReport(reportq.KindSsdeep, ssdeepItems)
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
		if m.API == nil {
			_ = m.enqueueReport(reportq.KindSsdeepCandidate, candidates)
		} else if resp, _, err := m.API.SendSsdeepCandidate(candidates); !reportOK(resp, err) {
			_ = m.History.Append("api.error", "sendSsdeepCandidate: "+errString(err, resp), nil)
			_ = m.enqueueReport(reportq.KindSsdeepCandidate, candidates)
		} else {
			_ = m.History.Append("api.ok", fmt.Sprintf("sendSsdeepCandidate (%d)", len(candidates)), nil)
		}
	}
}

func (m *Manager) sendScanLog(mode, desc, typ, runID string) {
	items := []api.ScanLogItem{{
		AgentID:     m.agentID(),
		Description: desc,
		TimeStamp:   time.Now().Format("2006-01-02 15:04:05"),
		Mode:        mode,
		Type:        typ,
		RunID:       runID,
	}}
	if m.API == nil {
		_ = m.enqueueReport(reportq.KindScanLog, items)
		_ = m.History.Append("api.warn", fmt.Sprintf("sendAgentScanLog queued (%s %s); Center API not linked yet", mode, typ), nil)
		return
	}
	if resp, _, err := m.API.SendAgentScanLog(items); !reportOK(resp, err) {
		_ = m.History.Append("api.error", "sendAgentScanLog: "+errString(err, resp), nil)
		_ = m.enqueueReport(reportq.KindScanLog, items)
		return
	}
	_ = m.History.Append("api.ok", fmt.Sprintf("sendAgentScanLog %s %s", mode, typ), map[string]any{
		"mode": mode, "type": typ, "run_id": runID, "agent_id": m.agentID(),
	})
}

func (m *Manager) enqueueReport(kind string, payload any) error {
	if m.ReportQ == nil {
		return nil
	}
	return m.ReportQ.Enqueue(kind, payload)
}

func reportOK(resp *api.Response, err error) bool {
	if err != nil {
		return false
	}
	if resp == nil {
		return false
	}
	return resp.StatusCode > 0 && resp.StatusCode < 400
}

func errString(err error, resp *api.Response) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil && resp.Error != "" {
		return resp.Error
	}
	if resp != nil {
		return fmt.Sprintf("status %d", resp.StatusCode)
	}
	return "unknown error"
}

func newScanRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
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
