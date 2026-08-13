package settings

// Product policy flags (set true to re-enable UI/behavior without deleting code).

// FeatureTargetedScanCustomPaths: when false, schedule/login use built-in path
// coverage only (Downloads/Desktop/Documents/Temp/AppData). When true, agents
// may also honor configured quick_scan_paths from settings/Center.
const FeatureTargetedScanCustomPaths = false

// Forced ssdeep policy (UI hidden; always applied on save/sync/startup).
const (
	ForcedSsdeepEnabled       = true
	ForcedSsdeepReportAPI     = true
	ForcedQuarantineOnDetect  = false
	ForcedSendSsdeepCandidate = true
)
