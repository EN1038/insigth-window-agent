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
// This keeps YARA integration simple in the first rewrite: YARA expects files.
func (s *Store) Materialize(destRoot string) ([]string, error) {
	idx, err := s.LoadIndex()
	if err != nil {
		return nil, err
	}
	if len(idx.Files) == 0 {
		return nil, fmt.Errorf("no rules in store")
	}

	kek, err := keystore.EnsureKEK(s.paths.VaultPath)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveSubkey(kek, "rules-blob")
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		return nil, err
	}
	_ = securefs.RestrictDirToSystemAndAdmins(destRoot)

	var entries []string
	for _, rec := range idx.Files {
		blobPath := filepath.Join(s.paths.DataDir, "rules", "blobs", rec.Blob)
		b, err := os.ReadFile(blobPath)
		if err != nil {
			return nil, err
		}
		env, err := crypto.Unmarshal(b)
		if err != nil {
			return nil, err
		}
		aad := []byte("rules-blob|v1|" + rec.RelPath)
		plain, err := crypto.OpenAESGCM(key, env, aad)
		if err != nil {
			return nil, err
		}

		outPath := filepath.Join(destRoot, filepath.FromSlash(rec.RelPath))
		if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(outPath, plain, 0o600); err != nil {
			return nil, err
		}

		base := strings.ToLower(filepath.Base(rec.RelPath))
		if base == "rules.yar" || base == "index.yar" || base == "rules_unified.yar" {
			entries = append(entries, outPath)
		}
	}
	if len(entries) == 0 {
		// fallback: return all .yar files as entrypoints
		for _, rec := range idx.Files {
			entries = append(entries, filepath.Join(destRoot, filepath.FromSlash(rec.RelPath)))
		}
	}
	return entries, nil
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

