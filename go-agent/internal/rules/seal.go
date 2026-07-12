package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/securefs"
)

// SealBundledPlaintext imports any plaintext .yar files bundled under
// installDir/Engine/Yara into the encrypted store located under dataDir, then
// securely removes the plaintext copies from disk. Safe to call repeatedly.
func SealBundledPlaintext(dataDir, installDir string) (imported int, version string, err error) {
	yarDir := filepath.Join(installDir, "Engine", "Yara")
	plain, err := listPlainYar(yarDir)
	if err != nil {
		return 0, "", err
	}
	if len(plain) == 0 {
		return 0, "", nil
	}

	store := New(dataDir)
	idx, err := store.LoadIndex()
	if err != nil {
		return 0, "", err
	}

	if len(idx.Files) == 0 {
		version, imported, err = store.ImportDirectory("bundled", yarDir)
		if err != nil {
			return 0, "", err
		}
	}

	if err := RemovePlaintextRuleFiles(yarDir); err != nil {
		return imported, version, err
	}
	return imported, version, nil
}

// RemovePlaintextRuleFiles securely deletes all .yar files under Engine/Yara.
func RemovePlaintextRuleFiles(yarDir string) error {
	return securefs.RemoveGlob(yarDir, "*.yar")
}

// WipeMaterializedDir securely removes a temporary rules materialization directory.
func WipeMaterializedDir(dir string) error {
	return securefs.WipeTree(dir)
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
