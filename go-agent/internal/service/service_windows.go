//go:build windows

package service

import (
	"context"
	"time"

	"github.com/sosecure/insite-agent/internal/app"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/install"
	winSvc "golang.org/x/sys/windows/svc"
)

func Run() error {
	// Always register with SCM when launched as `-mode service`.
	// Falling back to runConsole() when IsWindowsService() is false caused the
	// service to exit immediately (WIN32_EXIT_CODE 0) under LocalSystem.
	return winSvc.Run(install.ServiceName, &handler{})
}

type handler struct{}

func (h *handler) Execute(args []string, r <-chan winSvc.ChangeRequest, s chan<- winSvc.Status) (svcSpecificEC bool, exitCode uint32) {
	s <- winSvc.Status{State: winSvc.StartPending}
	s <- winSvc.Status{State: winSvc.Running, Accepts: winSvc.AcceptStop | winSvc.AcceptShutdown}

	baseDir := config.DataBaseDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	host, err := app.NewHost(baseDir)
	if err != nil {
		return false, 1
	}
	go func() { _ = host.Start(ctx) }()

	// Keep watchdog alive while main is running.
	go ensureWatchdogLoop(ctx)

	for c := range r {
		switch c.Cmd {
		case winSvc.Stop, winSvc.Shutdown:
			if authorizedServiceStop() {
				clearAuthorizedServiceStop()
				s <- winSvc.Status{State: winSvc.StopPending}
				cancel()
				s <- winSvc.Status{State: winSvc.Stopped}
				return
			}
			// Unauthorized stop: show credential UI and exit; watchdog will restart us.
			_ = launchConfirmStopUI()
			s <- winSvc.Status{State: winSvc.StopPending}
			cancel()
			// Give UI a moment to spawn before process exits.
			time.Sleep(400 * time.Millisecond)
			s <- winSvc.Status{State: winSvc.Stopped}
			return
		case winSvc.Interrogate:
			s <- c.CurrentStatus
		}
	}
	s <- winSvc.Status{State: winSvc.Stopped}
	return
}

func ensureWatchdogLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if authorizedServiceStop() {
				continue
			}
			running, err := isServiceRunning(install.WatchdogServiceName)
			if err != nil || running {
				continue
			}
			_ = startServiceByName(install.WatchdogServiceName)
		}
	}
}
