//go:build windows

package settings

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/winuser"
)

func pathNeedsUserEnv(tmpl string) bool {
	u := strings.ToUpper(tmpl)
	return strings.Contains(u, "%USERPROFILE%") ||
		strings.Contains(u, "%APPDATA%") ||
		strings.Contains(u, "%LOCALAPPDATA%") ||
		strings.Contains(u, "%TEMP%") ||
		strings.Contains(u, "%TMP%") ||
		strings.Contains(u, "%HOMEPATH%") ||
		strings.Contains(u, "%HOMEDRIVE%")
}

func quickScanProfileEnvs() []map[string]string {
	if !winuser.IsSystemProfile() {
		return nil
	}
	profiles := winuser.InteractiveProfiles()
	out := make([]map[string]string, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, map[string]string(p))
	}
	return out
}

func expandQuickPath(tmpl string, env map[string]string) string {
	return winuser.ExpandWithEnv(tmpl, winuser.ProfileEnv(env))
}

// realtimeProfileRoots returns consumer-AV style on-access roots under a user home.
func realtimeProfileRoots(home string) []string {
	home = strings.TrimSpace(home)
	if home == "" {
		return nil
	}
	local := filepath.Join(home, "AppData", "Local")
	roaming := filepath.Join(home, "AppData", "Roaming")
	return []string{
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Pictures"),
		filepath.Join(home, "Videos"),
		filepath.Join(local, "Temp"),
		filepath.Join(roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
	}
}

// RealtimeWatchRoots lists directories for realtime fsnotify coverage (market AV style:
// interactive user risk areas + configured quick-scan paths — not the whole disk).
func (s *Store) RealtimeWatchRoots() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		key := strings.ToLower(filepath.Clean(dir))
		if _, ok := seen[key]; ok {
			return
		}
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			seen[key] = struct{}{}
			out = append(out, dir)
		}
	}

	addProfile := func(home string) {
		for _, p := range realtimeProfileRoots(home) {
			add(p)
		}
	}

	if winuser.IsSystemProfile() {
		for _, env := range winuser.InteractiveProfiles() {
			addProfile(env["USERPROFILE"])
		}
	} else if profile := os.Getenv("USERPROFILE"); profile != "" {
		addProfile(profile)
	}

	for _, p := range s.QuickScanPaths() {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.IsDir() {
			add(p)
		} else {
			add(filepath.Dir(p))
		}
	}
	return out
}
