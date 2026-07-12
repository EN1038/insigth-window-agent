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
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install registers and starts the Go agent Windows service.
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

	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		_ = stopService(ServiceName)
		_ = uninstallService(m, ServiceName)
	}

	cfg := mgr.Config{
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "LocalSystem",
	}
	s, err := m.CreateService(ServiceName, exe, cfg, "-mode", "service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	_ = configureDelayedAuto(ServiceName)
	_ = configureRecovery(ServiceName)

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Uninstall stops and removes the Go agent service.
func Uninstall() error {
	_ = stopService(ServiceName)

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if err := uninstallService(m, ServiceName); err != nil {
		return err
	}
	return nil
}

// UpgradeFromLegacy stops legacy services/processes and installs the Go service.
// Data migration (config/settings) happens automatically on first service start.
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
