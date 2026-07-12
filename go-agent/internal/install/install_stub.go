//go:build !windows

package install

import "fmt"

func Install() error {
	return fmt.Errorf("service install is only supported on Windows")
}

func Uninstall() error {
	return fmt.Errorf("service uninstall is only supported on Windows")
}

func UpgradeFromLegacy() error {
	return fmt.Errorf("upgrade is only supported on Windows")
}

func StopLegacy() error { return nil }

func RemoveLegacyServices() error { return nil }

func LegacyServicesPresent() bool { return false }
