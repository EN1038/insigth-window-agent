package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/securefs"
)

// SealBundledPlaintext imports plaintext .yar files and optional ZIP packs bundled
// under installDir into the encrypted store, then removes plaintext from the
// install tree. Safe to call repeatedly.
//
// Lookup order:
//  1. installDir/Engine/Yara/*.yar (and nested)
//  2. installDir/Engine/Yara/*.zip
//  3. installDir/bundled/rules/*.zip (and repo go-agent/bundled/rules)
func SealBundledPlaintext(dataDir, installDir string) (imported int, version string, err error) {
	store := New(dataDir)
	idx, err := store.LoadIndex()
	if err != nil {
		return 0, "", err
	}
	// Only seed when store is empty — never clobber Center-synced rules.
	if len(idx.Files) > 0 {
		_ = removeBundledPlaintext(installDir)
		return 0, "", nil
	}

	yarDir := filepath.Join(installDir, "Engine", "Yara")
	if plain, listErr := listPlainYar(yarDir); listErr == nil && len(plain) > 0 {
		version, imported, err = store.ImportDirectory("bundled", yarDir)
		if err != nil {
			return 0, "", err
		}
	}

	for _, zipPath := range bundledRuleZipCandidates(installDir) {
		v, n, zerr := store.ImportZip(zipPath, "bundled")
		if zerr != nil {
			continue
		}
		imported += n
		if v != "" {
			version = v
		}
		// Wipe install-tree copies only (keep repo bundled zip for developers).
		if isUnder(zipPath, filepath.Join(installDir, "Engine")) {
			_ = securefs.WipeAndRemove(zipPath)
		}
	}

	_ = removeBundledPlaintext(installDir)
	return imported, version, nil
}

func removeBundledPlaintext(installDir string) error {
	yarDir := filepath.Join(installDir, "Engine", "Yara")
	return RemovePlaintextRuleFiles(yarDir)
}

// RemovePlaintextRuleFiles securely deletes all .yar files under Engine/Yara.
func RemovePlaintextRuleFiles(yarDir string) error {
	return securefs.RemoveGlob(yarDir, "*.yar")
}

// WipeMaterializedDir securely removes a temporary rules materialization directory.
func WipeMaterializedDir(dir string) error {
	return securefs.WipeTree(dir)
}

func bundledRuleZipCandidates(installDir string) []string {
	installDir = filepath.Clean(installDir)
	var out []string
	seen := map[string]bool{}
	addGlob := func(pattern string) {
		matches, _ := filepath.Glob(pattern)
		for _, p := range matches {
			p = filepath.Clean(p)
			if p == "" || seen[p] {
				continue
			}
			if st, err := os.Stat(p); err != nil || st.IsDir() || st.Size() == 0 {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	addGlob(filepath.Join(installDir, "Engine", "Yara", "*.zip"))
	addGlob(filepath.Join(installDir, "bundled", "rules", "*.zip"))
	for _, up := range []string{installDir, filepath.Dir(installDir), filepath.Dir(filepath.Dir(installDir))} {
		addGlob(filepath.Join(up, "bundled", "rules", "*.zip"))
	}
	return out
}

func isUnder(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func listPlainYar(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yar"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range matches {
		if strings.EqualFold(filepath.Ext(p), ".yar") {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".yar") {
				out = append(out, path)
			}
			return nil
		})
	}
	return out, nil
}
