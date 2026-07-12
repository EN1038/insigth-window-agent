package securefs

import (
	"os"
	"path/filepath"
)

// WipeAndRemove overwrites a file with zeros then deletes it.
func WipeAndRemove(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return WipeTree(path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		zeros := make([]byte, 4096)
		remain := info.Size()
		for remain > 0 {
			n := int64(len(zeros))
			if n > remain {
				n = remain
			}
			_, _ = f.Write(zeros[:n])
			remain -= n
		}
		_ = f.Close()
	}
	return os.Remove(path)
}

// WipeTree securely removes all files under root then deletes the directory.
func WipeTree(root string) error {
	if root == "" {
		return nil
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		_ = WipeAndRemove(path)
		return nil
	})
	return os.RemoveAll(root)
}

// RemoveGlob wipes and removes files matching pattern (e.g. "*.yar").
func RemoveGlob(dir, pattern string) error {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	for _, p := range matches {
		if err := WipeAndRemove(p); err != nil {
			return err
		}
	}
	return nil
}
