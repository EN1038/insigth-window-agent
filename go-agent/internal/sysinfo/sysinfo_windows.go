//go:build windows

package sysinfo

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Hostname returns device_name.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "UNKNOWN"
	}
	return h
}

// LocalIPv4 returns ip_private. Prefer an up RFC1918 interface address (stable on
// multi-NIC Server hosts); fall back to hostname DNS then any non-loopback IPv4.
func LocalIPv4() string {
	if ip := localIPv4FromInterfaces(); ip != "" && ip != "127.0.0.1" {
		return ip
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		if ips, err := net.LookupIP(h); err == nil {
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					s := v4.String()
					if isPrivateIPv4(s) {
						return s
					}
				}
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}
	return localIPv4FromInterfaces()
}

func localIPv4FromInterfaces() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			if (ifc.Flags&net.FlagUp) == 0 || (ifc.Flags&net.FlagLoopback) != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ip := addrToIPv4(a)
				if ip == "" {
					continue
				}
				// Prefer RFC1918 addresses.
				if isPrivateIPv4(ip) {
					return ip
				}
			}
		}
		// fallback: any non-loopback ipv4
		for _, ifc := range ifaces {
			if (ifc.Flags&net.FlagUp) == 0 || (ifc.Flags&net.FlagLoopback) != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ip := addrToIPv4(a)
				if ip != "" {
					return ip
				}
			}
		}
	}
	return "127.0.0.1"
}

func addrToIPv4(a net.Addr) string {
	switch v := a.(type) {
	case *net.IPNet:
		ip := v.IP.To4()
		if ip == nil {
			return ""
		}
		return ip.String()
	case *net.IPAddr:
		ip := v.IP.To4()
		if ip == nil {
			return ""
		}
		return ip.String()
	default:
		return ""
	}
}

func isPrivateIPv4(ip string) bool {
	// Cheap string checks.
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if parts[1] >= "16" && parts[1] <= "31" {
				return true
			}
		}
	}
	return false
}

// OsDescription returns a human-readable Windows version for dataInfo.
func OsDescription() string {
	if s := windowsProductLabel(); s != "" {
		return s
	}
	return runtime.GOOS + " " + runtime.GOARCH
}

// Domain is best-effort.
func Domain() string {
	// On Windows, USERDOMAIN is commonly present.
	if d := os.Getenv("USERDOMAIN"); d != "" {
		return d
	}
	return "-"
}

var (
	sysInfoOnce sync.Once
	sysInfoCached string
)

// SystemInfo collects manufacturer/model/CPU/RAM/OS for dataInfo (cached per process).
func SystemInfo() string {
	sysInfoOnce.Do(func() {
		sysInfoCached = buildSystemInfo()
	})
	if sysInfoCached == "" {
		return "-"
	}
	return sysInfoCached
}

func buildSystemInfo() string {
	parts := make([]string, 0, 4)

	mfr := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemManufacturer")
	model := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemProductName")
	hw := strings.TrimSpace(strings.Join([]string{mfr, model}, " "))
	if hw != "" {
		parts = append(parts, hw)
	}

	if cpu := strings.TrimSpace(regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")); cpu != "" {
		parts = append(parts, cpu)
	}

	if gb := totalRAMGiB(); gb > 0 {
		parts = append(parts, fmt.Sprintf("%dGB RAM", gb))
	}

	if osLabel := windowsProductLabel(); osLabel != "" {
		parts = append(parts, osLabel)
	}

	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func windowsProductLabel() string {
	product := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName")
	display := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "DisplayVersion")
	build := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuild")
	product = strings.TrimSpace(product)
	display = strings.TrimSpace(display)
	build = strings.TrimSpace(build)
	switch {
	case product != "" && display != "":
		return product + " " + display
	case product != "" && build != "":
		return product + " (build " + build + ")"
	case product != "":
		return product
	default:
		return ""
	}
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func totalRAMGiB() int {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	ret, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 || ms.TotalPhys == 0 {
		return 0
	}
	const gib = 1024 * 1024 * 1024
	gb := int((ms.TotalPhys + gib/2) / gib)
	if gb < 1 {
		gb = 1
	}
	return gb
}
