//go:build windows

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/securefs"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install registers and starts the main agent + watchdog services.
func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	if err := SecureLocalData(config.DataBaseDir(), filepath.Dir(exe)); err != nil {
		return fmt.Errorf("secure local data: %w", err)
	}

	if err := StopLegacy(); err != nil {
		return fmt.Errorf("stop legacy: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if err := recreateService(m, exe, ServiceName, ServiceDisplayName, ServiceDescription, "-mode", "service"); err != nil {
		return err
	}
	if err := recreateService(m, exe, WatchdogServiceName, WatchdogServiceDisplayName, WatchdogServiceDescription, "-mode", "watchdog"); err != nil {
		return err
	}

	if err := startService(m, ServiceName); err != nil {
		return fmt.Errorf("start main service: %w", err)
	}
	if err := startService(m, WatchdogServiceName); err != nil {
		return fmt.Errorf("start watchdog service: %w", err)
	}
	return nil
}

func recreateService(m *mgr.Mgr, exe, name, display, desc string, args ...string) error {
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		_ = stopService(name)
		_ = uninstallService(m, name)
		time.Sleep(500 * time.Millisecond)
	}
	cfg := mgr.Config{
		DisplayName:      display,
		Description:      desc,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
	}
	s, err := m.CreateService(name, exe, cfg, args...)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	s.Close()
	_ = configureDelayedAuto(name)
	_ = configureRecovery(name)
	return nil
}

func startService(m *mgr.Mgr, name string) error {
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

// Uninstall stops and removes main + watchdog services, then wipes all
// persistent agent data (site config, logs, rules, history, quarantine, etc.)
// so a later install starts completely clean.
func Uninstall() error {
	_ = stopService(WatchdogServiceName)
	_ = stopService(ServiceName)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	_ = uninstallService(m, WatchdogServiceName)
	if err := uninstallService(m, ServiceName); err != nil {
		return err
	}
	_ = wipePersistentData()
	return nil
}

func wipePersistentData() error {
	var first error
	record := func(err error) {
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}

	// Canonical store: %ProgramData%\SOSECURE Threat inSight
	// (config.enc, settings, history, rules, ssdeep, quarantine, IPC token, logs)
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	record(securefs.WipeTree(filepath.Join(pd, config.AppFolderName)))

	// Per-user UI runtime signals (best-effort; uninstall often runs as admin).
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		record(securefs.WipeTree(filepath.Join(la, config.AppFolderName)))
	}
	if ra := os.Getenv("APPDATA"); ra != "" {
		record(securefs.WipeTree(filepath.Join(ra, config.AppFolderName)))
	}
	return first
}

// UpgradeFromLegacy stops legacy services/processes and installs the Go services.
func UpgradeFromLegacy() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	installDir, err := filepath.Abs(filepath.Dir(exe))
	if err != nil {
		return err
	}

	if err := StopLegacy(); err != nil {
		return err
	}
	if err := RemoveLegacyServices(); err != nil {
		return err
	}
	if err := SecureLocalData(config.DataBaseDir(), installDir); err != nil {
		return fmt.Errorf("secure local data: %w", err)
	}
	return Install()
}

func uninstallService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		if isServiceNotFound(err) {
			return nil
		}
		return err
	}
	defer s.Close()
	return s.Delete()
}

func stopService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		if isServiceNotFound(err) {
			return nil
		}
		return err
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	_, err = s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout stopping %s", name)
}

func configureDelayedAuto(name string) error {
	return runSc("config", fmt.Sprintf(`"%s"`, name), "start=", "delayed-auto")
}

func configureRecovery(name string) error {
	return runSc("failure", fmt.Sprintf(`"%s"`, name),
		"reset=", "86400",
		"actions=", "restart/60000/restart/60000/restart/60000")
}

func runSc(args ...string) error {
	cmd := exec.Command("sc.exe", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s: %s", err, msg)
	}
	return nil
}

func isServiceNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "does not exist") ||
		strings.Contains(strings.ToLower(err.Error()), "marked for deletion")
}
