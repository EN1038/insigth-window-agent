package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ImportDir imports plaintext .yar/.yara rule files from a directory tree into the encrypted store.
// relPrefix is prepended to stored relative paths (use "" for none).
// It returns the number of rule files imported.
func (s *Store) ImportDir(srcDir string, ruleID int64, relPrefix string) (int, error) {
	srcDir = strings.TrimSpace(srcDir)
	if srcDir == "" {
		return 0, fmt.Errorf("empty srcDir")
	}
	info, err := os.Stat(srcDir)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("not a directory: %s", srcDir)
	}

	idx, err := s.LoadIndex()
	if err != nil {
		return 0, err
	}
	if idx.Files == nil {
		idx.Files = map[string]Record{}
	}

	relPrefix = normalizeRel(relPrefix)
	if relPrefix != "" && !strings.HasSuffix(relPrefix, "/") {
		relPrefix += "/"
	}

	imported := 0
	walkErr := filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		rel = normalizeRel(rel)
		if rel == "" {
			return nil
		}
		rel = relPrefix + rel

		plain, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rec, err := s.Put(ruleID, rel, plain)
		if err != nil {
			return err
		}
		// Use rel path as stable key.
		idx.Files[rel] = rec
		imported++
		return nil
	})
	if walkErr != nil {
		return imported, walkErr
	}

	if imported == 0 {
		return 0, nil
	}
	if err := s.SaveIndex(idx); err != nil {
		return imported, err
	}
	return imported, nil
}

