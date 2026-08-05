package scan

import (
	"context"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/settings"
)

type Scheduler struct {
	Manager  *Manager
	Settings *settings.Store
}

func NewScheduler(m *Manager, st *settings.Store) *Scheduler {
	return &Scheduler{Manager: m, Settings: st}
}

func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Scheduler) tick() {
	if s.Manager == nil || s.Settings == nil || s.Manager.IsScanning() {
		return
	}
	mins := settings.NormalizeIntervalMinutes(
		s.Settings.Get(settings.KeyBatchJobEveryDay, ""),
		settings.DefaultBatchIntervalMinutes,
	)
	last := s.Settings.Get(settings.KeyLastBatchJobRun, "")
	now := time.Now()
	// First boot / empty stamp: IntervalDue("") == true. Arm the clock without
	// scanning so install + first login does not look like "auto scan on login".
	if strings.TrimSpace(last) == "" {
		s.Settings.Set(settings.KeyLastBatchJobRun, settings.FormatIntervalRunStamp(now))
		_ = s.Settings.Save()
		return
	}
	if !settings.IntervalDue(last, mins, now) {
		return
	}
	// Only stamp last-run after the scan actually starts.
	if !s.Manager.StartScheduledQuickScan() {
		return
	}
	s.Settings.Set(settings.KeyLastBatchJobRun, settings.FormatIntervalRunStamp(now))
	_ = s.Settings.Save()
}
