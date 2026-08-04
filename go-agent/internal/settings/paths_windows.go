//go:build windows

package settings

import (
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
