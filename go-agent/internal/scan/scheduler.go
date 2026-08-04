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
	mins := settings.NormalizeIntervalMinutes(
		s.Settings.Get(settings.KeyBatchJobEveryDay, ""),
		settings.DefaultBatchIntervalMinutes,
	)
	last := s.Settings.Get(settings.KeyLastBatchJobRun, "")
	now := time.Now()
	if !settings.IntervalDue(last, mins, now) {
		return
	}
	s.Settings.Set(settings.KeyLastBatchJobRun, settings.FormatIntervalRunStamp(now))
	_ = s.Settings.Save()
	s.Manager.StartQuickScan()
}
