package scan

import "time"

const (
	batchSize  = 5000
	queueCap   = 10000
	scanWorkers = 1
)

type StatusInfo struct {
	Scanning bool   `json:"scanning"`
	ScanType string `json:"scan_type"`
	Scanned  int    `json:"scanned"`
	Total    int    `json:"total"`
	Skipped  int    `json:"skipped"`
	Threats  int    `json:"threats"`
	Status   string `json:"status"`
}


type ScanType string

const (
	ScanQuick  ScanType = "quick"
	ScanFull   ScanType = "full"
	ScanAuto   ScanType = "auto"
	ScanCustom ScanType = "custom"
	ScanSilent ScanType = "silent"
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
	case scanType == ScanAuto:
		return "AUTO_SCAN"
	case scanType == ScanSilent:
		return "REALTIME_SCAN"
	case scanSource == "USB":
		return "USB_SCAN"
	case scanType == ScanCustom:
		return "CUSTOM_SCAN"
	default:
		return "MANUAL_SCAN"
	}
}
