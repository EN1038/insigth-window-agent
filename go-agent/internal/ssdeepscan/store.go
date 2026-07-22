package ssdeepscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/securefs"
	"github.com/sosecure/insite-agent/internal/storage"
)

// Signature is one fuzzy-hash entry (scan payload only — no SQLite).
type Signature struct {
	Name string `json:"n"`
	Hash string `json:"h"`
}

// Index is the encrypted catalog of block-size shards.
type Index struct {
	Version   int            `json:"version"`
	UpdatedAt string         `json:"updated_at"`
	Total     int            `json:"total"`
	Blocks    map[string]int `json:"blocks"` // block_size -> count
}

// Store keeps ssdeep signatures under Data/ssdeep using the same
// vault + AES-256-GCM envelope pattern as rules/settings.
type Store struct {
	paths config.Paths
	root  string
}

func NewStore(baseDir string) *Store {
	p := config.ResolvePaths(baseDir)
	return &Store{
		paths: p,
		root:  filepath.Join(p.DataDir, "ssdeep"),
	}
}

func DefaultStoreDir(dataDir string) string {
	return filepath.Join(dataDir, "ssdeep")
}

func (s *Store) indexPath() string {
	return filepath.Join(s.root, "index.enc")
}

func (s *Store) shardPath(blockSize int) string {
	return filepath.Join(s.root, "shards", fmt.Sprintf("%d.shardenc", blockSize))
}

func (s *Store) LoadIndex() (*Index, error) {
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      s.indexPath(),
		Purpose:   "ssdeep-index",
		AAD:       "ssdeep-index|v1",
	}
	var idx Index
	if err := enc.Load(&idx); err != nil {
		if os.IsNotExist(err) {
			return &Index{Version: 1, Blocks: map[string]int{}}, nil
		}
		return nil, err
	}
	if idx.Blocks == nil {
		idx.Blocks = map[string]int{}
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
	if idx.Blocks == nil {
		idx.Blocks = map[string]int{}
	}
	idx.Version = 1
	idx.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      s.indexPath(),
		Purpose:   "ssdeep-index",
		AAD:       "ssdeep-index|v1",
	}
	return enc.Save(idx)
}

func (s *Store) LoadShard(blockSize int) ([]Signature, error) {
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      s.shardPath(blockSize),
		Purpose:   "ssdeep-shard",
		AAD:       fmt.Sprintf("ssdeep-shard|v1|%d", blockSize),
	}
	var list []Signature
	if err := enc.Load(&list); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return list, nil
}

func (s *Store) SaveShard(blockSize int, list []Signature) error {
	if err := os.MkdirAll(filepath.Join(s.root, "shards"), 0o700); err != nil {
		return err
	}
	enc := storage.EncryptedJSON{
		VaultPath: s.paths.VaultPath,
		Path:      s.shardPath(blockSize),
		Purpose:   "ssdeep-shard",
		AAD:       fmt.Sprintf("ssdeep-shard|v1|%d", blockSize),
	}
	return enc.Save(list)
}

// ReplaceAll writes a full set of shards and refreshes the index.
func (s *Store) ReplaceAll(byBlock map[int][]Signature) error {
	if err := os.MkdirAll(filepath.Join(s.root, "shards"), 0o700); err != nil {
		return err
	}
	// Remove old shards so stale block sizes disappear.
	_ = clearDir(filepath.Join(s.root, "shards"))

	idx := &Index{Version: 1, Blocks: map[string]int{}}
	total := 0
	for bs, list := range byBlock {
		if bs <= 0 || len(list) == 0 {
			continue
		}
		if err := s.SaveShard(bs, list); err != nil {
			return err
		}
		idx.Blocks[strconv.Itoa(bs)] = len(list)
		total += len(list)
	}
	idx.Total = total
	return s.SaveIndex(idx)
}

func (s *Store) Total() (int, error) {
	idx, err := s.LoadIndex()
	if err != nil {
		return 0, err
	}
	return idx.Total, nil
}

// HasEncryptedStore reports whether an encrypted index already exists.
func (s *Store) HasEncryptedStore() bool {
	_, err := os.Stat(s.indexPath())
	return err == nil
}

// LegacySQLitePath is the old plaintext DB path (migration source only).
func (s *Store) LegacySQLitePath() string {
	return filepath.Join(s.root, "signatures.db")
}

// ImportJSONFile loads a JSON array of {name, ssdeep} (optional family) into encrypted shards.
func (s *Store) ImportJSONFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	type row struct {
		Name   string `json:"name"`
		Family string `json:"family"`
		Ssdeep string `json:"ssdeep"`
	}
	var rows []row
	if err := json.Unmarshal(b, &rows); err != nil {
		return 0, err
	}
	byBlock := map[int][]Signature{}
	for _, r := range rows {
		hash := strings.TrimSpace(r.Ssdeep)
		if hash == "" {
			continue
		}
		bs, ok := parseBlockSize(hash)
		if !ok {
			continue
		}
		name := strings.TrimSpace(r.Name)
		if fam := strings.TrimSpace(r.Family); fam != "" {
			name = name + " (" + fam + ")"
		}
		if name == "" {
			name = "unknown"
		}
		byBlock[bs] = append(byBlock[bs], Signature{Name: name, Hash: hash})
	}
	if err := s.ReplaceAll(byBlock); err != nil {
		return 0, err
	}
	return countMap(byBlock), nil
}

func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		_ = securefs.WipeAndRemove(filepath.Join(dir, e.Name()))
	}
	return nil
}

func parseBlockSize(hash string) (int, bool) {
	for i := 0; i < len(hash); i++ {
		if hash[i] == ':' {
			n, err := strconv.Atoi(hash[:i])
			return n, err == nil && n > 0
		}
	}
	return 0, false
}

func countMap(m map[int][]Signature) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func stringsTrim(s string) string {
	return strings.TrimSpace(s)
}
