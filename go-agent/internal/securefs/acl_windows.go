//go:build windows

package securefs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RestrictDirToSystemAndAdmins removes inherited ACLs and grants full control
// only to SYSTEM and Administrators. Regular users cannot list or read files.
func RestrictDirToSystemAndAdmins(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	quoted := quoteICACLS(dir)
	args := []string{
		quoted, "/inheritance:r",
		"/grant:r", `SYSTEM:(OI)(CI)F`,
		"/grant:r", `Administrators:(OI)(CI)F`,
	}
	return runICACLS(args...)
}

// RestrictEngineYara allows only SYSTEM/Admins to access the YARA engine folder.
// yara64.exe must remain executable by the service (LocalSystem).
func RestrictEngineYara(baseDir string) error {
	dir := filepath.Join(baseDir, "Engine", "Yara")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	quoted := quoteICACLS(dir)
	args := []string{
		quoted, "/inheritance:r",
		"/grant:r", `SYSTEM:(OI)(CI)F`,
		"/grant:r", `Administrators:(OI)(CI)F`,
	}
	return runICACLS(args...)
}

func quoteICACLS(p string) string {
	p = filepath.Clean(p)
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

func runICACLS(args ...string) error {
	cmd := exec.Command("icacls.exe", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("icacls: %s", msg)
	}
	return nil
}
