//go:build windows

package sysinfo

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// Hostname returns device_name.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "UNKNOWN"
	}
	return h
}

// LocalIPv4 returns ip_private using the same approach as the legacy .NET agent:
// Dns.GetHostEntry(hostname).AddressList -> first IPv4. Falls back to interface scan.
func LocalIPv4() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		if ips, err := net.LookupIP(h); err == nil {
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

// OsDescription is best-effort; WMI enrichment can be added later.
func OsDescription() string {
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

// SystemInfo is best-effort.
func SystemInfo() string {
	return "-"
}

