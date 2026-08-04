package runtime

import (
	"context"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/login"
	"github.com/sosecure/insite-agent/internal/quarantine"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/snapshot"
	"github.com/sosecure/insite-agent/internal/usb"
	"github.com/sosecure/insite-agent/internal/watcher"
)

type ScanRuntime struct {
	Manager   *scan.Manager
	Scheduler *scan.Scheduler
	Watcher   *watcher.Watcher
	USB       *usb.Monitor
	Login     *login.Monitor
}

func NewScanRuntime(baseDir string, st *settings.Store, snap *snapshot.Store, apiClient *api.Client, hist *history.Store, ruleStore *rules.Store) *ScanRuntime {
	quar := quarantine.New(baseDir, st.Get(settings.KeyQuarantinePath, ""))
	_ = quar.Load()
	mgr := scan.NewManager(baseDir, st, snap, apiClient, hist, ruleStore, quar)
	return &ScanRuntime{
		Manager:   mgr,
		Scheduler: scan.NewScheduler(mgr, st),
		Watcher:   watcher.New(mgr, st),
		USB:       usb.New(mgr, st),
		Login:     login.New(mgr, st),
	}
}

func (sr *ScanRuntime) Run(ctx context.Context) {
	if sr == nil {
		return
	}
	go sr.Scheduler.Run(ctx)
	go sr.Watcher.Run(ctx)
	go sr.USB.Run(ctx)
	if sr.Login != nil {
		go sr.Login.Run(ctx)
	}
	<-ctx.Done()
}

func (sr *ScanRuntime) RefreshRules() {
	if sr != nil && sr.Manager != nil {
		sr.Manager.RefreshRules()
	}
}

func (sr *ScanRuntime) RefreshSsdeep() {
	if sr != nil && sr.Manager != nil {
		sr.Manager.RefreshSsdeep()
	}
}
