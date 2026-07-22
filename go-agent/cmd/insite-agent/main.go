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
	mode := flag.String("mode", "auto", "auto|service|watchdog|ui|confirm-stop|confirm-exit|setup|install|uninstall|upgrade|seal")
	flag.Parse()

	switch *mode {
	case "service":
		if err := service.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "watchdog":
		if err := service.RunWatchdog(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "ui":
		if err := service.RunUI(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "confirm-stop":
		if err := service.RunConfirmStopUI(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "confirm-exit":
		if err := service.RunConfirmExitUI(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "setup":
		if !install.IsAdmin() {
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
		fmt.Println("Services installed and started:")
		fmt.Println(" -", install.ServiceName)
		fmt.Println(" -", install.WatchdogServiceName)
	case "uninstall":
		if err := install.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Services removed:", install.ServiceName, "+", install.WatchdogServiceName)
	case "upgrade":
		if err := install.UpgradeFromLegacy(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Upgraded from legacy to:", install.ServiceName, "+", install.WatchdogServiceName)
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
