//go:build !windows

package settings

import "os"

func pathNeedsUserEnv(string) bool { return false }

func quickScanProfileEnvs() []map[string]string { return nil }

func expandQuickPath(tmpl string, _ map[string]string) string {
	return os.ExpandEnv(tmpl)
}
