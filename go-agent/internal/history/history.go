package history

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/crypto"
	"github.com/sosecure/insite-agent/internal/keystore"
)

// Store is an append-only encrypted event log to support UI "recent activity"
// and offline troubleshooting. It is not designed for complex local queries.
//
// File format: one JSON Envelope per line (AES-256-GCM).
type Store struct {
	paths config.Paths
}

func New(baseDir string) *Store {
	return &Store{paths: config.ResolvePaths(baseDir)}
}

type Event struct {
	TimeRFC3339 string `json:"time"`
	Kind        string `json:"kind"` // e.g. "scan.start", "scan.end", "rule.sync", "api.error"
	Message     string `json:"message"`
	Meta        any    `json:"meta,omitempty"`
}

func (s *Store) Append(kind, msg string, meta any) error {
	if err := os.MkdirAll(s.paths.DataDir, 0o700); err != nil {
		return err
	}

	ev := Event{
		TimeRFC3339: time.Now().Format(time.RFC3339),
		Kind:        kind,
		Message:     msg,
		Meta:        meta,
	}
	plain, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	kek, err := keystore.EnsureKEK(s.paths.VaultPath)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveSubkey(kek, "history")
	if err != nil {
		return err
	}
	aad := []byte("history|v1")

	env, err := crypto.SealAESGCM(key, plain, aad)
	if err != nil {
		return err
	}
	line, err := crypto.Marshal(env)
	if err != nil {
		return err
	}

	p := s.dayPath(time.Now())
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// ReadRecent reads up to limit newest events from today, then yesterday, etc.
// It is intentionally simple and bounded.
func (s *Store) ReadRecent(daysBack int, limit int) ([]Event, error) {
	if limit <= 0 {
		return nil, nil
	}
	kek, err := keystore.EnsureKEK(s.paths.VaultPath)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveSubkey(kek, "history")
	if err != nil {
		return nil, err
	}
	aad := []byte("history|v1")

	var out []Event
	for i := 0; i <= daysBack && len(out) < limit; i++ {
		day := time.Now().AddDate(0, 0, -i)
		p := s.dayPath(day)
		evs, _ := readAll(p, key, aad) // ignore missing files
		// append from newest end
		for j := len(evs) - 1; j >= 0 && len(out) < limit; j-- {
			out = append(out, evs[j])
		}
	}
	return out, nil
}

func (s *Store) dayPath(t time.Time) string {
	name := fmt.Sprintf("history_%s.logenc", t.Format("20060102"))
	return filepath.Join(s.paths.DataDir, name)
}

func readAll(path string, key []byte, aad []byte) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		env, err := crypto.Unmarshal(line)
		if err != nil {
			continue
		}
		pt, err := crypto.OpenAESGCM(key, env, aad)
		if err != nil {
			continue
		}
		var ev Event
		if err := json.Unmarshal(pt, &ev); err != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

