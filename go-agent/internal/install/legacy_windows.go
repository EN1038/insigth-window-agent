//go:build windows

package install

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func legacyServiceNames() []string {
	return []string{
		legacyServiceWatchdog,
		legacyServiceMain,
		legacyServiceWatchdogAlt,
		legacyServiceMainAlt,
	}
}

// StopLegacy stops legacy .NET services and related processes.
func StopLegacy() error {
	for _, name := range legacyServiceNames() {
		_ = runSc("control", fmt.Sprintf(`"%s"`, name), "128")
		time.Sleep(2 * time.Second)
		_ = runSc("stop", fmt.Sprintf(`"%s"`, name))
		time.Sleep(time.Second)
	}
	for _, img := range []string{"sosecure-engine.exe", "insight.sosecure.legacy.exe", "yara64.exe"} {
		cmd := exec.Command("taskkill", "/F", "/IM", img)
		_, _ = cmd.CombinedOutput()
	}
	return nil
}

// RemoveLegacyServices deletes legacy Windows service registrations.
func RemoveLegacyServices() error {
	for _, name := range legacyServiceNames() {
		_ = stopService(name)
		_ = runSc("delete", fmt.Sprintf(`"%s"`, name))
	}
	return nil
}

// LegacyServicesPresent reports whether old .NET services are still registered.
func LegacyServicesPresent() bool {
	for _, name := range legacyServiceNames() {
		cmd := exec.Command("sc.exe", "query", name)
		out, err := cmd.CombinedOutput()
		if err == nil && !strings.Contains(string(out), "FAILED") {
			return true
		}
	}
	return false
}
