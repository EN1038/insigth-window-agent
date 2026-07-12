package quarantine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	dir      string
	metaPath string
	items    []Metadata
}

type Metadata struct {
	ID           string
	OriginalPath string
	FileName     string
	ThreatType   string
	IsolatedUnix int64
}

func New(baseDir, quarantinePath string) *Store {
	if quarantinePath == "" {
		quarantinePath = filepath.Join(baseDir, "Quarantine")
	}
	return &Store{
		dir:      quarantinePath,
		metaPath: filepath.Join(quarantinePath, "quarantine.dat"),
	}
}

func (s *Store) Load() error {
	_ = os.MkdirAll(s.dir, 0o700)
	s.items = nil
	b, err := os.ReadFile(s.metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.Split(ln, "|")
		if len(parts) < 5 {
			continue
		}
		var ticks int64
		fmt.Sscanf(parts[4], "%d", &ticks)
		s.items = append(s.items, Metadata{
			ID:           parts[0],
			OriginalPath: parts[1],
			FileName:     parts[2],
			ThreatType:   parts[3],
			IsolatedUnix: ticks,
		})
	}
	return nil
}

func (s *Store) Save() error {
	lines := make([]string, 0, len(s.items))
	for _, m := range s.items {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%d", m.ID, m.OriginalPath, m.FileName, m.ThreatType, m.IsolatedUnix))
	}
	return os.WriteFile(s.metaPath, []byte(strings.Join(lines, "\n")), 0o600)
}

func (s *Store) Isolate(filePath, threatType string) bool {
	if _, err := os.Stat(filePath); err != nil {
		return false
	}
	_ = os.MkdirAll(s.dir, 0o700)
	id := randomID()
	dest := filepath.Join(s.dir, id+".qfile")
	if err := os.Rename(filePath, dest); err != nil {
		return false
	}
	s.items = append(s.items, Metadata{
		ID:           id,
		OriginalPath: filePath,
		FileName:     filepath.Base(filePath),
		ThreatType:   threatType,
		IsolatedUnix: time.Now().Unix(),
	})
	_ = s.Save()
	return true
}

// List returns a copy of all quarantined item metadata (newest first).
func (s *Store) List() []Metadata {
	out := make([]Metadata, len(s.items))
	copy(out, s.items)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
