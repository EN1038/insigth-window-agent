package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/storage"
)

// Store is a baseline/incremental cache. For initial rewrite we keep a simple
// full-save encrypted snapshot file. We can later evolve to append/compact like
// the legacy SnapshotStore when needed.
type Store struct {
	paths  config.Paths
	Record map[string]FileRecord `json:"record"`
}

type FileRecord struct {
	Size            int64  `json:"size"`
	LastWriteUnix   int64  `json:"last_write_unix"`
	CreateUnix      int64  `json:"create_unix"`
	RulesVersion    string `json:"rules_version"`
	LastScanResult  string `json:"last_scan_result"` // clean|infected
	LastScanUnix    int64  `json:"last_scan_unix"`
}

// NeedsRescan decides whether a file should be scanned again.
// Incremental skip uses size + mtime + rulesVersion only (not content hash).
// Rare false-skips: content changes that preserve size and mtime.
// Optional later: ContentHash (SHA-256/xxhash) when size+mtime match.
func (r FileRecord) NeedsRescan(size int64, lastWriteUnix int64, rulesVersion string) bool {
	if r.LastScanResult == "" {
		return true
	}
	if r.Size != size {
		return true
	}
	if r.LastWriteUnix != lastWriteUnix {
		return true
	}
	if rulesVersion != "" && r.RulesVersion != rulesVersion {
		return true
	}
	return false
}

func New(baseDir string) *Store {
	return &Store{
		paths:  config.ResolvePaths(baseDir),
		Record: map[string]FileRecord{},
	}
}

func (s *Store) Load() error {
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "snapshot.enc"),
		Purpose:   "snapshot",
		AAD:       "snapshot|v1",
	}
	type payload struct {
		Record map[string]FileRecord `json:"record"`
	}
	var p payload
	if err := enc.Load(&p); err != nil {
		if os.IsNotExist(err) {
			s.Record = map[string]FileRecord{}
			return nil
		}
		return err
	}
	if p.Record == nil {
		p.Record = map[string]FileRecord{}
	}
	s.Record = p.Record
	return nil
}

func (s *Store) Save() error {
	_ = os.MkdirAll(s.paths.DataDir, 0o700)
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "snapshot.enc"),
		Purpose:   "snapshot",
		AAD:       "snapshot|v1",
	}
	type payload struct {
		Record map[string]FileRecord `json:"record"`
		Saved  string               `json:"saved"`
	}
	return enc.Save(payload{Record: s.Record, Saved: time.Now().Format(time.RFC3339)})
}

func (s *Store) Upsert(path string, rec FileRecord) {
	if s.Record == nil {
		s.Record = map[string]FileRecord{}
	}
	s.Record[path] = rec
}

func (s *Store) Get(path string) (FileRecord, bool) {
	r, ok := s.Record[path]
	return r, ok
}

// ExportJSON is for debugging only (never used by service).
func (s *Store) ExportJSON() ([]byte, error) {
	return json.Marshal(s)
}

