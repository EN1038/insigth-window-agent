//go:build windows

package install

import (
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/securefs"
	"github.com/sosecure/insite-agent/internal/settings"
)

// SecureLocalData encrypts bundled rules, removes plaintext secrets/rules from disk,
// and restricts sensitive directories so regular users cannot read them.
//
// dataDir is the persistent data root (%ProgramData%); installDir is where the
// executable and engine binaries live. Engine/Yara operations use installDir,
// while all encrypted stores and hardened directories use dataDir.
func SecureLocalData(dataDir, installDir string) error {
	imported, ver, err := rules.SealBundledPlaintext(dataDir, installDir)
	if err != nil {
		return err
	}
	if ver != "" && imported > 0 {
		st := settings.New(dataDir)
		if loadErr := st.Load(); loadErr == nil {
			st.Set(settings.KeyRulesVersion, ver)
			_ = st.Save()
		}
	}

	// Legacy plaintext config.json is wiped only after config.enc is verified
	// readable; that safe wipe happens inside config.Load, so we do not remove it
	// here (avoids permanently losing config if config.enc becomes unreadable).
	return hardenSensitiveDirs(dataDir, installDir)
}

func hardenSensitiveDirs(dataDir, installDir string) error {
	dirs := []string{
		filepath.Join(dataDir, "Data"),
		filepath.Join(dataDir, "Data", "rules"),
		filepath.Join(dataDir, "Data", "rules", "blobs"),
		filepath.Join(dataDir, "Config", "Key"),
		filepath.Join(dataDir, "Quarantine"),
	}
	for _, d := range dirs {
		_ = securefs.RestrictDirToSystemAndAdmins(d)
	}
	_ = securefs.RestrictEngineYara(installDir)
	return nil
}
