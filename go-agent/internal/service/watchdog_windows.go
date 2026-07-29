//go:build windows

package service

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/install"
	"github.com/sosecure/insite-agent/internal/settings"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// RunWatchdog runs the mutual-watch service that restarts the main agent if
// it was stopped without an authorized credential confirm.
func RunWatchdog() error {
	// Always register with SCM when launched as `-mode watchdog`.
	return svc.Run(install.WatchdogServiceName, &watchdogHandler{})
}

type watchdogHandler struct{}

func (h *watchdogHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runWatchdogLoop(ctx) }()

	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			if !authorizedServiceStop() {
				_ = launchConfirmStopUI()
			} else {
				clearAuthorizedServiceStop()
			}
			s <- svc.Status{State: svc.StopPending}
			cancel()
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		case svc.Interrogate:
			s <- c.CurrentStatus
		}
	}
	s <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runWatchdogLoop(ctx context.Context) error {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			watchOnce()
		}
	}
}

func watchOnce() {
	if authorizedServiceStop() {
		return
	}
	running, err := isServiceRunning(install.ServiceName)
	if err != nil || running {
		return
	}
	_ = startServiceByName(install.ServiceName)
	_ = launchConfirmStopUI()
}

func authorizedServiceStop() bool {
	st := settings.New(config.DataBaseDir())
	_ = st.Load()
	return st.GetBool(settings.KeyAuthorizedServiceStop)
}

func clearAuthorizedServiceStop() {
	st := settings.New(config.DataBaseDir())
	_ = st.Load()
	st.Set(settings.KeyAuthorizedServiceStop, "false")
	_ = st.Save()
}

func SetAuthorizedServiceStop(v bool) {
	st := settings.New(config.DataBaseDir())
	_ = st.Load()
	if v {
		st.Set(settings.KeyAuthorizedServiceStop, "true")
	} else {
		st.Set(settings.KeyAuthorizedServiceStop, "false")
	}
	_ = st.Save()
}

func launchConfirmStopUI() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-mode", "confirm-stop")
	cmd.Dir = filepath.Dir(exe)
	return cmd.Start()
}

func isServiceRunning(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running || st.State == svc.StartPending, nil
}

func startServiceByName(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Running || st.State == svc.StartPending {
		return nil
	}
	return s.Start()
}

func stopServiceByName(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	_, err = s.Control(svc.Stop)
	return err
}

// StopProtectionAuthorized marks stop as authorized then stops main + watchdog.
func StopProtectionAuthorized() error {
	SetAuthorizedServiceStop(true)
	_ = stopServiceByName(install.ServiceName)
	_ = stopServiceByName(install.WatchdogServiceName)
	return nil
}
