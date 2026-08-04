package settings

import (
	"strconv"
	"strings"
	"time"
)

// Interval minute presets (must match Center AgentScheduleInterval::PRESETS).
var IntervalPresets = []int{1, 5, 10, 15, 20, 25, 30, 45, 60, 120, 180, 360, 720, 1440}

const (
	DefaultBatchIntervalMinutes        = 1440
	DefaultTISyncIntervalMinutes       = 60
	DefaultAgentUpdateIntervalMinutes  = 360
)

// IntervalPresetLabels returns display labels parallel to IntervalPresets.
func IntervalPresetLabels() []string {
	out := make([]string, len(IntervalPresets))
	for i, m := range IntervalPresets {
		out[i] = IntervalLabel(m)
	}
	return out
}

func IntervalLabel(minutes int) string {
	if minutes < 60 {
		if minutes == 1 {
			return "Every 1 minute"
		}
		return "Every " + strconv.Itoa(minutes) + " minutes"
	}
	if minutes%60 == 0 {
		h := minutes / 60
		if h == 1 {
			return "Every 1 hour"
		}
		return "Every " + strconv.Itoa(h) + " hours"
	}
	return "Every " + strconv.Itoa(minutes) + " minutes"
}

// NormalizeIntervalMinutes maps legacy HH:mm or free-form values onto a preset.
func NormalizeIntervalMinutes(raw string, defaultMinutes int) int {
	def := snapPreset(defaultMinutes)
	s := strings.TrimSpace(raw)
	if s == "" {
		return def
	}
	if strings.Contains(s, ":") {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	return snapPreset(n)
}

func snapPreset(m int) int {
	if m < 1 {
		m = 1
	}
	for _, p := range IntervalPresets {
		if p == m {
			return m
		}
	}
	best := IntervalPresets[0]
	bestDist := absInt(best - m)
	for _, p := range IntervalPresets {
		d := absInt(p - m)
		if d < bestDist || (d == bestDist && p > best) {
			best = p
			bestDist = d
		}
	}
	return best
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// IntervalDue reports whether enough time has elapsed since lastRun.
// lastRun may be RFC3339 or legacy YYYY-MM-DD.
func IntervalDue(lastRun string, intervalMinutes int, now time.Time) bool {
	mins := intervalMinutes
	if mins < 1 {
		mins = 1
	}
	last := strings.TrimSpace(lastRun)
	if last == "" {
		return true
	}
	var t time.Time
	var err error
	if t, err = time.Parse(time.RFC3339, last); err != nil {
		if t, err = time.ParseInLocation("2006-01-02", last, now.Location()); err != nil {
			return true
		}
	}
	return !now.Before(t.Add(time.Duration(mins) * time.Minute))
}

// FormatIntervalRunStamp stores last-run as RFC3339.
func FormatIntervalRunStamp(t time.Time) string {
	return t.Format(time.RFC3339)
}

// IntervalSelectIndex finds select index for a stored value.
func IntervalSelectIndex(raw string, defaultMinutes int) int {
	n := NormalizeIntervalMinutes(raw, defaultMinutes)
	for i, p := range IntervalPresets {
		if p == n {
			return i
		}
	}
	return 0
}
