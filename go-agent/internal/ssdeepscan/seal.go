package ssdeepscan

import (
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/securefs"
)

// BundledSQLiteName is the plaintext signature database shipped with the installer
// (sealed into Data/ssdeep on first run, then removed from the install tree).
const BundledSQLiteName = "signatures.db"

// BundledSQLiteCandidates returns paths to look for a plaintext signatures.db,
// in priority order (install layout first, then repo dev bundle).
func BundledSQLiteCandidates(installDir string) []string {
	installDir = filepath.Clean(installDir)
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(filepath.Join(installDir, "Engine", "Ssdeep", BundledSQLiteName))
	add(filepath.Join(installDir, "bundled", "ssdeep", BundledSQLiteName))
	// Dev: exe in go-agent/dist or cmd, bundle under go-agent/bundled/ssdeep.
	for _, up := range []string{installDir, filepath.Dir(installDir), filepath.Dir(filepath.Dir(installDir))} {
		add(filepath.Join(up, "bundled", "ssdeep", BundledSQLiteName))
	}
	return out
}

// SealBundledSignatures imports plaintext bundled signatures.db into the encrypted
// store when no encrypted index exists yet. Matches the YARA bundled-rules flow.
func SealBundledSignatures(dataDir, installDir string) (imported int, err error) {
	store := NewStore(dataDir)
	if store.HasEncryptedStore() {
		return 0, nil
	}
	src := findBundledSQLite(installDir)
	if src == "" {
		return 0, nil
	}
	n, err := store.ImportFromSQLite(src)
	if err != nil {
		return 0, err
	}
	// Remove plaintext copy from installer tree only (keep repo dev bundle).
	_ = removeInstallEngineCopy(installDir)
	return n, nil
}

func findBundledSQLite(installDir string) string {
	for _, p := range BundledSQLiteCandidates(installDir) {
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

func removeInstallEngineCopy(installDir string) error {
	p := filepath.Join(installDir, "Engine", "Ssdeep", BundledSQLiteName)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		_ = securefs.WipeAndRemove(p)
	}
	return nil
}
