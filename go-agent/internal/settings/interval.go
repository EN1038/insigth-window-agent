package settings

import (
	"strconv"
	"strings"
	"time"
)

// Interval minute presets (must match Center AgentScheduleInterval::PRESETS).
// Used for TI sync — NOT batch scan / agent update.
var IntervalPresets = []int{1, 5, 10, 15, 20, 25, 30, 45, 60, 120, 180, 360, 720, 1440}

// AgentUpdateDayPresets: every N days (stored as minutes = days * 1440).
var AgentUpdateDayPresets = []int{1, 3, 7, 14, 30, 60, 90}

const (
	DefaultBatchDailyHHmm             = "02:00"
	DefaultTISyncIntervalMinutes      = 60
	DefaultAgentUpdateIntervalMinutes = 1440 // every 1 day
)

// AgentUpdateIntervalPresets returns minute values for agent update day cadence.
func AgentUpdateIntervalPresets() []int {
	out := make([]int, len(AgentUpdateDayPresets))
	for i, d := range AgentUpdateDayPresets {
		out[i] = d * 1440
	}
	return out
}

// AgentUpdatePresetLabels returns labels parallel to AgentUpdateIntervalPresets.
func AgentUpdatePresetLabels() []string {
	out := make([]string, len(AgentUpdateDayPresets))
	for i, d := range AgentUpdateDayPresets {
		out[i] = AgentUpdateLabelDays(d)
	}
	return out
}

func AgentUpdateLabelDays(days int) string {
	if days <= 1 {
		return "Every day"
	}
	return "Every " + strconv.Itoa(days) + " days"
}

// NormalizeAgentUpdateMinutes maps stored/API values onto day presets (minutes).
func NormalizeAgentUpdateMinutes(raw string, defaultMinutes int) int {
	def := snapAgentUpdateMinutes(defaultMinutes)
	s := strings.TrimSpace(raw)
	if s == "" || strings.Contains(s, ":") {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	return snapAgentUpdateMinutes(n)
}

func snapAgentUpdateMinutes(m int) int {
	if m < 1 {
		m = DefaultAgentUpdateIntervalMinutes
	}
	presets := AgentUpdateIntervalPresets()
	for _, p := range presets {
		if p == m {
			return m
		}
	}
	// Bare day counts (1–90) → minutes.
	for _, d := range AgentUpdateDayPresets {
		if m == d {
			return d * 1440
		}
	}
	best := presets[0]
	bestDist := absInt(best - m)
	for _, p := range presets {
		d := absInt(p - m)
		if d < bestDist || (d == bestDist && p > best) {
			best = p
			bestDist = d
		}
	}
	return best
}

// AgentUpdateSelectIndex finds select index for a stored agent-update value.
func AgentUpdateSelectIndex(raw string) int {
	n := NormalizeAgentUpdateMinutes(raw, DefaultAgentUpdateIntervalMinutes)
	presets := AgentUpdateIntervalPresets()
	for i, p := range presets {
		if p == n {
			return i
		}
	}
	return 0
}

// DailyTimePresets returns HH:mm options every 30 minutes (matches Center Control Agent).
func DailyTimePresets() []string {
	out := make([]string, 0, 48)
	for h := 0; h < 24; h++ {
		for _, m := range []int{0, 30} {
			out = append(out, formatHHmm(h, m))
		}
	}
	return out
}

func formatHHmm(hour, minute int) string {
	return pad2(hour) + ":" + pad2(minute)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// NormalizeDailyHHmm maps stored/API batch values to HH:mm.
// Legacy interval-minute strings (no colon) become defaultTime.
func NormalizeDailyHHmm(raw, defaultTime string) string {
	def := snapDailyHHmm(defaultTime, DefaultBatchDailyHHmm)
	s := strings.TrimSpace(raw)
	if s == "" || !strings.Contains(s, ":") {
		return def
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return def
	}
	hour, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	minute, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return def
	}
	switch {
	case minute < 15:
		minute = 0
	case minute < 45:
		minute = 30
	default:
		minute = 0
		hour = (hour + 1) % 24
	}
	return formatHHmm(hour, minute)
}

func snapDailyHHmm(raw, fallback string) string {
	s := strings.TrimSpace(raw)
	if s == "" || !strings.Contains(s, ":") {
		return fallback
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return fallback
	}
	hour, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	minute, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return fallback
	}
	switch {
	case minute < 15:
		minute = 0
	case minute < 45:
		minute = 30
	default:
		minute = 0
		hour = (hour + 1) % 24
	}
	return formatHHmm(hour, minute)
}

// DailyTimeSelectIndex finds select index for a stored HH:mm value.
func DailyTimeSelectIndex(raw string) int {
	n := NormalizeDailyHHmm(raw, DefaultBatchDailyHHmm)
	presets := DailyTimePresets()
	for i, p := range presets {
		if p == n {
			return i
		}
	}
	return 0
}

// DailyDue reports whether now matches schedule HH:mm and has not run today.
func DailyDue(scheduleHHmm, lastRun string, now time.Time) bool {
	sched := NormalizeDailyHHmm(scheduleHHmm, DefaultBatchDailyHHmm)
	parts := strings.Split(sched, ":")
	if len(parts) < 2 {
		return false
	}
	hour, err1 := strconv.Atoi(parts[0])
	minute, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if now.Hour() != hour || now.Minute() != minute {
		return false
	}
	today := now.Format("2006-01-02")
	last := strings.TrimSpace(lastRun)
	if last == "" {
		return true
	}
	if last == today || strings.HasPrefix(last, today) {
		return false
	}
	if t, err := time.Parse(time.RFC3339, last); err == nil {
		return t.In(now.Location()).Format("2006-01-02") != today
	}
	if t, err := time.ParseInLocation("2006-01-02", last, now.Location()); err == nil {
		return t.Format("2006-01-02") != today
	}
	return true
}

// FormatDailyRunStamp stores last daily run as YYYY-MM-DD.
func FormatDailyRunStamp(t time.Time) string {
	return t.Format("2006-01-02")
}

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
