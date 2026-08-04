//go:build windows

package winuser

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	wtsActive          = 0
	wtsConnected       = 1
	profileSkipDefault = true
)

var (
	wtsapi32              = syscall.NewLazyDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory         = wtsapi32.NewProc("WTSFreeMemory")
)

type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

// ProfileEnv maps common user-scoped env vars for path expansion.
type ProfileEnv map[string]string

// ActiveSessionIDs returns interactive session IDs that are Active or Connected.
func ActiveSessionIDs() []uint32 {
	var count uint32
	var pInfo uintptr
	r1, _, _ := procWTSEnumerateSessionsW.Call(0, 0, 1, uintptr(unsafe.Pointer(&pInfo)), uintptr(unsafe.Pointer(&count)))
	if r1 == 0 || pInfo == 0 || count == 0 {
		return nil
	}
	defer procWTSFreeMemory.Call(pInfo)

	out := make([]uint32, 0, count)
	size := unsafe.Sizeof(wtsSessionInfo{})
	for i := uint32(0); i < count; i++ {
		info := (*wtsSessionInfo)(unsafe.Pointer(pInfo + uintptr(i)*size))
		if info.SessionID == 0 {
			continue // services session
		}
		if info.State != wtsActive && info.State != wtsConnected {
			continue
		}
		out = append(out, info.SessionID)
	}
	return out
}

// InteractiveProfiles returns profile env maps for local interactive users
// (directories under C:\Users). Used when the agent runs as SYSTEM so
// %USERPROFILE% / %APPDATA% / %TEMP% resolve to real user folders.
func InteractiveProfiles() []ProfileEnv {
	root := filepath.Join(`C:\Users`)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []ProfileEnv
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if shouldSkipProfileDir(name) {
			continue
		}
		home := filepath.Join(root, name)
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			continue
		}
		local := filepath.Join(home, "AppData", "Local")
		roaming := filepath.Join(home, "AppData", "Roaming")
		temp := filepath.Join(local, "Temp")
		out = append(out, ProfileEnv{
			"USERPROFILE":  home,
			"HOMEPATH":     `\Users\` + name,
			"HOMEDRIVE":    `C:`,
			"APPDATA":      roaming,
			"LOCALAPPDATA": local,
			"TEMP":         temp,
			"TMP":          temp,
		})
	}
	return out
}

func shouldSkipProfileDir(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "desktop.ini":
		return profileSkipDefault
	default:
		return false
	}
}

// ExpandWithEnv expands %VAR% using the given map, falling back to process env.
func ExpandWithEnv(path string, env ProfileEnv) string {
	if path == "" {
		return ""
	}
	return os.Expand(path, func(key string) string {
		if env != nil {
			if v, ok := env[strings.ToUpper(key)]; ok {
				return v
			}
			if v, ok := env[key]; ok {
				return v
			}
		}
		return os.Getenv(key)
	})
}

// IsSystemProfile reports whether the process USERPROFILE looks like the
// Windows service/system profile (not a real interactive user).
func IsSystemProfile() bool {
	p := strings.ToLower(os.Getenv("USERPROFILE"))
	if p == "" {
		return true
	}
	return strings.Contains(p, `\windows\system32\config\systemprofile`) ||
		strings.Contains(p, `\windows\serviceprofiles\`)
}
