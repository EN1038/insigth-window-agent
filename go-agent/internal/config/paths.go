package config

import (
	"os"
	"path/filepath"
)

type Paths struct {
	BaseDir    string
	ConfigDir  string
	DataDir    string
	LogDir     string
	VaultPath  string
	ConfigPath string
	LegacyPath string
}

func ResolvePaths(baseDir string) Paths {
	return Paths{
		BaseDir:    baseDir,
		ConfigDir:  filepath.Join(baseDir, "Config", "Key"),
		DataDir:    filepath.Join(baseDir, "Data"),
		LogDir:     filepath.Join(baseDir, "Logs"),
		VaultPath:  filepath.Join(baseDir, "Data", "vault.bin"),
		ConfigPath: filepath.Join(baseDir, "Config", "Key", "config.enc"),
		LegacyPath: filepath.Join(baseDir, "Config", "Key", "config.json"),
	}
}

func ExeBaseDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// AppFolderName is the fixed folder name used under %ProgramData% for all
// persistent agent data (config, settings, history, rules, quarantine).
const AppFolderName = "SOSECURE Threat inSight"

// DataBaseDir returns the single canonical data root shared by BOTH the service
// and the UI, regardless of where the executable is launched from. This prevents
// the UI (or a stray copy of the exe) from creating a second data store in the
// wrong directory and losing the saved config.
func DataBaseDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	dir := filepath.Join(pd, AppFolderName)
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// InstallDir returns the directory of the running executable. Engine binaries
// (yara64.exe and any bundled rules) ship next to the exe and are read from here,
// separately from the persistent data root returned by DataBaseDir.
func InstallDir() string {
	if d, err := ExeBaseDir(); err == nil && d != "" {
		return d
	}
	return DataBaseDir()
}

