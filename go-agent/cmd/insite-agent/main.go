package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/install"
	"github.com/sosecure/insite-agent/internal/service"
	winSvc "golang.org/x/sys/windows/svc"
)

func main() {
	mode := flag.String("mode", "auto", "auto|service|ui|setup|install|uninstall|upgrade|seal")
	flag.Parse()

	switch *mode {
	case "service":
		if err := service.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "ui":
		if err := service.RunUI(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "setup":
		// One-click installer: elevates, installs service to Program Files, launches UI.
		if !install.IsAdmin() {
			// Relaunch elevated and exit current process.
			_ = install.RunElevated("-mode", "setup")
			return
		}
		if err := install.SetupOneClick(true); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "install":
		if err := install.Install(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Service installed and started:", install.ServiceName)
	case "uninstall":
		if err := install.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Service removed:", install.ServiceName)
	case "upgrade":
		if err := install.UpgradeFromLegacy(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Upgraded from legacy to:", install.ServiceName)
	case "seal":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		installDir, err := filepath.Abs(filepath.Dir(exe))
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		if err := install.SecureLocalData(config.DataBaseDir(), installDir); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Local data sealed (rules encrypted, plaintext removed, ACL hardened)")
	case "auto":
		isService, err := winSvc.IsWindowsService()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		if isService {
			if err := service.Run(); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		}
		if err := service.RunUI(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "invalid -mode")
		os.Exit(2)
	}
}
