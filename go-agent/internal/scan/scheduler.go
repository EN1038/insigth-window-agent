package scan

import (
	"context"
	"strconv"
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
	schedule := s.Settings.Get(settings.KeyBatchJobEveryDay, "02:00")
	parts := strings.Split(schedule, ":")
	if len(parts) < 2 {
		return
	}
	hour, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	minute, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return
	}
	now := time.Now()
	if now.Hour() != hour || now.Minute() != minute {
		return
	}
	today := now.Format("2006-01-02")
	if s.Settings.Get(settings.KeyLastBatchJobRun, "") == today {
		return
	}
	s.Settings.Set(settings.KeyLastBatchJobRun, today)
	_ = s.Settings.Save()
	s.Manager.StartQuickScan()
}
