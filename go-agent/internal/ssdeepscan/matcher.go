package ssdeepscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/glaslos/ssdeep"
)

const (
	DefaultMinFileSize = 4 * 1024
	DefaultMaxFileSize = 50 * 1024 * 1024
	DefaultThreshold   = 85
)

var defaultExtensions = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".ps1": true,
	".bat": true, ".js": true, ".apk": true, ".php": true,
	".so": true, ".scr": true, ".com": true, ".cmd": true,
}

// Match is one ssdeep hit against the encrypted signature store.
type Match struct {
	Path   string
	Name   string
	Score  int
	Ssdeep string
}

// Matcher fuzzy-hashes files and compares against AES-GCM shards.
type Matcher struct {
	store     *Store
	threshold int
	minSize   int64
	maxSize   int64

	mu         sync.Mutex
	shardCache map[int][]Signature
	ready      bool
}

func NewMatcher(baseDir string, threshold int) *Matcher {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Matcher{
		store:      NewStore(baseDir),
		threshold:  threshold,
		minSize:    DefaultMinFileSize,
		maxSize:    DefaultMaxFileSize,
		shardCache: map[int][]Signature{},
	}
}

func (m *Matcher) Store() *Store { return m.store }

func (m *Matcher) SetThreshold(threshold int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	m.threshold = threshold
}

func (m *Matcher) Reload() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shardCache = map[int][]Signature{}
	m.ready = false
}

func (m *Matcher) Eligible(path string, size int64) bool {
	if size < m.minSize || size > m.maxSize {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	return defaultExtensions[ext]
}

// EnsureReady migrates legacy signatures.db into encrypted shards once, if needed.
func (m *Matcher) EnsureReady() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ready {
		return nil
	}
	if m.store.HasEncryptedStore() {
		m.ready = true
		return nil
	}
	legacy := m.store.LegacySQLitePath()
	if st, err := os.Stat(legacy); err == nil && st.Size() > 0 {
		if _, err := m.store.ImportFromSQLite(legacy); err != nil {
			return fmt.Errorf("migrate ssdeep sqlite: %w", err)
		}
		// Drop plaintext DB after successful encrypt (no need to zero a 100MB+ file).
		_ = os.Remove(legacy)
	}
	m.ready = true
	return nil
}

// FuzzyHashFile returns the ssdeep fuzzy hash of path, or "" if unavailable.
func FuzzyHashFile(path string) string {
	hash, err := ssdeep.FuzzyFilename(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hash)
}

func (m *Matcher) ScanCleanFiles(paths []string, sizes map[string]int64, stopped func() bool) ([]Match, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if err := m.EnsureReady(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var out []Match
	for _, path := range paths {
		if stopped != nil && stopped() {
			break
		}
		size := sizes[path]
		if size == 0 {
			if st, err := os.Stat(path); err == nil {
				size = st.Size()
			}
		}
		if !m.Eligible(path, size) {
			continue
		}
		hit, ok, err := m.matchLocked(path)
		if err != nil || !ok {
			continue
		}
		out = append(out, hit)
	}
	return out, nil
}

func (m *Matcher) matchLocked(path string) (Match, bool, error) {
	hash, err := ssdeep.FuzzyFilename(path)
	if err != nil || hash == "" {
		return Match{}, false, err
	}
	parts := strings.Split(hash, ":")
	if len(parts) < 3 {
		return Match{}, false, nil
	}
	blockSize, err := strconv.Atoi(parts[0])
	if err != nil {
		return Match{}, false, nil
	}

	for _, bs := range []int{blockSize / 2, blockSize, blockSize * 2} {
		if bs <= 0 {
			continue
		}
		sigs, err := m.shardLocked(bs)
		if err != nil {
			return Match{}, false, err
		}
		for _, sig := range sigs {
			score, err := ssdeep.Distance(hash, sig.Hash)
			if err == nil && score >= m.threshold {
				return Match{
					Path:   path,
					Name:   sig.Name,
					Score:  score,
					Ssdeep: hash,
				}, true, nil
			}
		}
	}
	return Match{}, false, nil
}

func (m *Matcher) shardLocked(blockSize int) ([]Signature, error) {
	if cached, ok := m.shardCache[blockSize]; ok {
		return cached, nil
	}
	list, err := m.store.LoadShard(blockSize)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []Signature{}
	}
	m.shardCache[blockSize] = list
	return list, nil
}

// RuleLabel formats a threat rule string for logging/quarantine.
func RuleLabel(name string, score int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unknown"
	}
	return fmt.Sprintf("ssdeep:%s@%d", name, score)
}
