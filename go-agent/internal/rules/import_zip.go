package rules

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/securefs"
)

// ImportZip extracts a downloaded rule ZIP and stores .yar files encrypted.
func (s *Store) ImportZip(zipPath, ruleSetName string) (version string, count int, err error) {
	if ruleSetName == "" {
		ruleSetName = "server"
	}
	tempDir, err := os.MkdirTemp("", "insite_zip_*")
	if err != nil {
		return "", 0, err
	}
	defer securefs.WipeTree(tempDir)

	if err := extractZip(zipPath, tempDir); err != nil {
		return "", 0, err
	}
	return s.ImportDirectory(ruleSetName, tempDir)
}

// ImportDirectory walks a directory and imports all .yar files into the encrypted store.
func (s *Store) ImportDirectory(ruleSetName, rootDir string) (string, int, error) {
	version, err := hashDirectory(rootDir)
	if err != nil {
		return "", 0, err
	}

	idx, err := s.LoadIndex()
	if err != nil {
		return "", 0, err
	}

	count := 0
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".yar") {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}
		rel = normalizeRel(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rec, err := s.Put(0, rel, data)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%s", ruleSetName, rel)
		idx.Files[key] = rec
		count++
		return nil
	})
	if err != nil {
		return "", count, err
	}
	if count == 0 {
		return "", 0, fmt.Errorf("no .yar files in %s", rootDir)
	}
	if err := s.SaveIndex(idx); err != nil {
		return "", count, err
	}
	return version, count, nil
}

func extractZip(zipPath, dest string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	destClean := filepath.Clean(dest)
	for _, f := range reader.File {
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(filepath.Clean(target), destClean+string(os.PathSeparator)) {
			return fmt.Errorf("illegal zip path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func hashDirectory(root string) (string, error) {
	h := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".yar") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = normalizeRel(rel)
		io.WriteString(h, rel)
		io.WriteString(h, "\n")
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		io.WriteString(h, "\n")
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}
