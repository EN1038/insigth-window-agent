package rules

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/crypto"
	"github.com/sosecure/insite-agent/internal/keystore"
	"github.com/sosecure/insite-agent/internal/securefs"
	"github.com/sosecure/insite-agent/internal/storage"
)

// Store persists encrypted YARA rule files with a small encrypted index.
// This replaces SQLCipher for the agent rewrite.
type Store struct {
	paths config.Paths
}

func New(baseDir string) *Store {
	return &Store{paths: config.ResolvePaths(baseDir)}
}

type Index struct {
	Version   int               `json:"version"`
	UpdatedAt string            `json:"updated_at"`
	Files     map[string]Record `json:"files"` // key: rule_id:path or just path; we keep flexible
}

type Record struct {
	RelPath string `json:"rel_path"`
	Blob    string `json:"blob"` // filename under Data/rules/blobs/
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	RuleID  int64  `json:"rule_id"`
}

func (s *Store) LoadIndex() (*Index, error) {
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "rules", "index.enc"),
		Purpose:   "rules-index",
		AAD:       "rules-index|v1",
	}
	var idx Index
	if err := enc.Load(&idx); err != nil {
		if os.IsNotExist(err) {
			return &Index{Version: 1, UpdatedAt: time.Now().Format(time.RFC3339), Files: map[string]Record{}}, nil
		}
		return nil, err
	}
	if idx.Files == nil {
		idx.Files = map[string]Record{}
	}
	if idx.Version == 0 {
		idx.Version = 1
	}
	return &idx, nil
}

func (s *Store) SaveIndex(idx *Index) error {
	if idx == nil {
		return fmt.Errorf("nil index")
	}
	idx.UpdatedAt = time.Now().Format(time.RFC3339)
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      filepath.Join(s.paths.DataDir, "rules", "index.enc"),
		Purpose:   "rules-index",
		AAD:       "rules-index|v1",
	}
	return enc.Save(idx)
}

// FileCount returns how many encrypted rule files are registered in the index.
func (s *Store) FileCount() int {
	idx, err := s.LoadIndex()
	if err != nil || idx == nil {
		return 0
	}
	return len(idx.Files)
}

// Clear wipes the encrypted YARA rule store (index + blobs) so the next sync
// can rebuild exactly what Center assigned to this site.
func (s *Store) Clear() error {
	idxPath := filepath.Join(s.paths.DataDir, "rules", "index.enc")
	_ = os.Remove(idxPath)
	blobsDir := filepath.Join(s.paths.DataDir, "rules", "blobs")
	_ = securefs.WipeTree(blobsDir)
	return os.MkdirAll(blobsDir, 0o700)
}

// PutIndexed stores one rule file and writes it into the index under ruleSet:relPath.
func (s *Store) PutIndexed(ruleSetName, relPath string, plain []byte) error {
	if ruleSetName == "" {
		ruleSetName = "server"
	}
	idx, err := s.LoadIndex()
	if err != nil {
		return err
	}
	rec, err := s.Put(0, relPath, plain)
	if err != nil {
		return err
	}
	idx.Files[fmt.Sprintf("%s:%s", ruleSetName, normalizeRel(relPath))] = rec
	return s.SaveIndex(idx)
}

// Put stores one rule file content encrypted as a blob on disk and updates the index.
func (s *Store) Put(ruleID int64, relPath string, plain []byte) (Record, error) {
	relPath = normalizeRel(relPath)
	if relPath == "" {
		return Record{}, fmt.Errorf("empty relPath")
	}
	if err := os.MkdirAll(filepath.Join(s.paths.DataDir, "rules", "blobs"), 0o700); err != nil {
		return Record{}, err
	}

	kek, err := keystore.EnsureKEK(s.paths.VaultPath)
	if err != nil {
		return Record{}, err
	}
	key, err := crypto.DeriveSubkey(kek, "rules-blob")
	if err != nil {
		return Record{}, err
	}

	// Random blob file name (opaque).
	name := make([]byte, 16)
	if _, err := rand.Read(name); err != nil {
		return Record{}, err
	}
	blobFile := fmt.Sprintf("%x.blobenc", name)
	blobPath := filepath.Join(s.paths.DataDir, "rules", "blobs", blobFile)

	aad := []byte("rules-blob|v1|" + relPath)
	env, err := crypto.SealAESGCM(key, plain, aad)
	if err != nil {
		return Record{}, err
	}
	out, err := crypto.Marshal(env)
	if err != nil {
		return Record{}, err
	}
	if err := os.WriteFile(blobPath, out, 0o600); err != nil {
		return Record{}, err
	}

	rec := Record{
		RelPath: relPath,
		Blob:    blobFile,
		Size:    int64(len(plain)),
		SHA256:  "", // filled later when we add hashing for verification
		RuleID:  ruleID,
	}
	return rec, nil
}

// Materialize decrypts all stored rule blobs to destRoot and returns entry .yar file paths.
// It deduplicates overlapping packs, skips unsupported modules, and prunes files that
// fail to compile with the bundled yara64 so scans actually produce matches.
func (s *Store) Materialize(destRoot string) ([]string, error) {
	_, entries, err := s.MaterializeWithStats(destRoot)
	return entries, err
}

// MaterializeWithStats is like Materialize but also returns selection/prune stats.
func (s *Store) MaterializeWithStats(destRoot string) (MaterializeStats, []string, error) {
	started := time.Now()
	stats := MaterializeStats{}

	idx, err := s.LoadIndex()
	if err != nil {
		return stats, nil, err
	}
	if len(idx.Files) == 0 {
		return stats, nil, fmt.Errorf("no rules in store")
	}

	kek, err := keystore.EnsureKEK(s.paths.VaultPath)
	if err != nil {
		return stats, nil, err
	}
	key, err := crypto.DeriveSubkey(kek, "rules-blob")
	if err != nil {
		return stats, nil, err
	}

	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		return stats, nil, err
	}

	var written []string
	seenRel := map[string]bool{}
	for _, rec := range idx.Files {
		blobPath := filepath.Join(s.paths.DataDir, "rules", "blobs", rec.Blob)
		b, err := os.ReadFile(blobPath)
		if err != nil {
			return stats, nil, err
		}
		env, err := crypto.Unmarshal(b)
		if err != nil {
			return stats, nil, err
		}
		aad := []byte("rules-blob|v1|" + rec.RelPath)
		plain, err := crypto.OpenAESGCM(key, env, aad)
		if err != nil {
			return stats, nil, err
		}

		rel := normalizeRel(rec.RelPath)
		if rel == "" || seenRel[strings.ToLower(rel)] {
			continue
		}
		seenRel[strings.ToLower(rel)] = true

		outPath := filepath.Join(destRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
			return stats, nil, err
		}
		if err := os.WriteFile(outPath, plain, 0o600); err != nil {
			return stats, nil, err
		}
		written = append(written, rel)
	}
	if len(written) == 0 {
		return stats, nil, fmt.Errorf("no rule entry files materialized")
	}
	stats.StoredFiles = len(written)

	selected := buildScanIncludeList(destRoot, written)
	beforePrune := len(selected)
	if yaraExe := resolveBundledYara(s.paths.BaseDir); yaraExe != "" {
		selected = pruneFailingIncludes(destRoot, yaraExe, selected)
	} else if yaraExe := resolveBundledYara(filepath.Dir(s.paths.DataDir)); yaraExe != "" {
		selected = pruneFailingIncludes(destRoot, yaraExe, selected)
	}
	stats.PrunedFiles = beforePrune - len(selected)
	stats.SelectedFiles = len(selected)
	if len(selected) == 0 {
		return stats, nil, fmt.Errorf("no usable YARA rules after dedupe/prune (stored=%d)", len(written))
	}

	allPath, err := writeInsiteAll(destRoot, selected)
	if err != nil {
		return stats, nil, err
	}
	stats.Duration = time.Since(started)
	return stats, []string{allPath}, nil
}

func normalizeRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimLeft(p, "/")
	return p
}

// DebugIndexJSON returns a plaintext JSON snapshot (for debugging only).
func (s *Store) DebugIndexJSON() ([]byte, error) {
	idx, err := s.LoadIndex()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(idx, "", "  ")
}

