package scan

import "time"

const (
	// One file per yara64.exe invocation to keep peak CPU lower (slower overall).
	batchSize = 1
	queueCap  = 10000
	scanWorkers = 1
	// Pause between yara invocations so the host can breathe between files.
	yaraFileDelay = 80 * time.Millisecond
)

type StatusInfo struct {
	Scanning      bool   `json:"scanning"`
	ScanType      string `json:"scan_type"`
	Source        string `json:"source"` // Manual|Schedule|Login|USB|Realtime
	Scanned       int    `json:"scanned"`
	Total         int    `json:"total"`
	Skipped       int    `json:"skipped"`
	Threats       int    `json:"threats"`
	Status        string `json:"status"` // discovering|scanning|completed|stopped|error|idle|finalizing
	Message       string `json:"message"`
	CurrentFile   string `json:"current_file"`   // basename for compact UI
	CurrentPath   string `json:"current_path"`   // full path
	CurrentEngine string `json:"current_engine"` // yara|ssdeep|discover|""
	DiscoveryDone bool   `json:"discovery_done"` // false while enumerator still running
}


type ScanType string

const (
	// ScanTargeted = path-limited coverage (schedule / login). Not a user-facing "Quick Scan".
	ScanTargeted ScanType = "targeted"
	ScanFull     ScanType = "full"
	ScanCustom   ScanType = "custom"
	ScanSilent   ScanType = "silent"
)

type FileItem struct {
	Path          string
	Size          int64
	LastWriteUnix int64
	CreateUnix    int64
}

type Threat struct {
	Path     string
	Rule     string
	ScanType ScanType
	Engine   string // "yara" | "ssdeep"
	Score    int    // ssdeep similarity score when Engine == "ssdeep"
	// Ssdeep fuzzy hash of the file (ssdeep hits; computed at report time for YARA).
	Ssdeep string
}

type Result struct {
	ScanType      ScanType
	ScanSource    string
	RulesVersion  string
	StartTime     time.Time
	EndTime       time.Time
	TotalFound    int
	FilesScanned  int
	FilesSkipped  int
	ThreatsFound  int
	Status        string
	Threats       []Threat
}

func (r Result) Duration() time.Duration {
	if r.EndTime.IsZero() {
		return time.Since(r.StartTime)
	}
	return r.EndTime.Sub(r.StartTime)
}

func APIMode(scanType ScanType, scanSource string) string {
	switch {
	case scanSource == SourceSchedule:
		return "SCHEDULE_SCAN"
	case scanSource == SourceLogin:
		return "LOGIN_SCAN"
	case scanType == ScanSilent || scanSource == SourceRealtime:
		return "REALTIME_SCAN"
	case scanSource == SourceUSB || scanSource == "USB":
		return "USB_SCAN"
	case scanType == ScanCustom:
		return "CUSTOM_SCAN"
	case scanType == ScanFull:
		return "FULL_SCAN"
	default:
		// Manual on-demand leftovers (should not appear for schedule/login/USB/realtime).
		return "MANUAL_SCAN"
	}
}

// Scan trigger sources (stored on Result.ScanSource / API mode).
const (
	SourceManual   = "Manual"
	SourceSchedule = "Schedule"
	SourceLogin    = "Login"
	SourceUSB      = "USB"
	SourceRealtime = "Realtime"
)
