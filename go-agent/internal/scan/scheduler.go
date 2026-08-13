package scan

import (
	"context"
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
	schedule := settings.NormalizeDailyHHmm(
		s.Settings.Get(settings.KeyBatchJobEveryDay, ""),
		settings.DefaultBatchDailyHHmm,
	)
	last := s.Settings.Get(settings.KeyLastBatchJobRun, "")
	now := time.Now()
	if !settings.DailyDue(schedule, last, now) {
		return
	}
	// Only stamp last-run after the scan actually starts.
	if !s.Manager.StartScheduledScan() {
		return
	}
	s.Settings.Set(settings.KeyLastBatchJobRun, settings.FormatDailyRunStamp(now))
	_ = s.Settings.Save()
}
