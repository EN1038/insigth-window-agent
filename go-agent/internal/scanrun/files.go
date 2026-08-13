package scanrun

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileRecord is one engine-scanned path for a run (not incremental skips).
type FileRecord struct {
	Path      string  `json:"path"`
	Result    string  `json:"result"` // clean|infected
	Rule      string  `json:"rule,omitempty"`
	Engine    string  `json:"engine,omitempty"`
	Score     float64 `json:"score,omitempty"`
	ScannedAt string  `json:"scanned_at,omitempty"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func New(baseDir string) *Store {
	dir := filepath.Join(baseDir, "Data", "scan_runs")
	_ = os.MkdirAll(dir, 0o700)
	return &Store{dir: dir}
}

func (s *Store) pathFor(runID string) string {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		runID = "unknown"
	}
	// Keep filename safe.
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, runID)
	return filepath.Join(s.dir, safe+".jsonl")
}

// Append writes records for a run (JSONL). Safe for concurrent writers via mutex.
func (s *Store) Append(runID string, records []FileRecord) error {
	if s == nil || len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.MkdirAll(s.dir, 0o700)
	f, err := os.OpenFile(s.pathFor(runID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}

// List returns up to limit records for a run (newest-first if reverse).
func (s *Store) List(runID string, offset, limit int) (rows []FileRecord, total int, err error) {
	if s == nil {
		return nil, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.pathFor(runID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer f.Close()

	all := make([]FileRecord, 0, 256)
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r FileRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		all = append(all, r)
	}
	total = len(all)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []FileRecord{}, total, nil
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return all[offset:end], total, sc.Err()
}

// ListByRunEnds groups recent scan.end-compatible listing: infected first within page is left to caller.
func SortInfectedFirst(rows []FileRecord) []FileRecord {
	if len(rows) < 2 {
		return rows
	}
	out := make([]FileRecord, 0, len(rows))
	for _, r := range rows {
		if strings.EqualFold(r.Result, "infected") {
			out = append(out, r)
		}
	}
	for _, r := range rows {
		if !strings.EqualFold(r.Result, "infected") {
			out = append(out, r)
		}
	}
	return out
}
