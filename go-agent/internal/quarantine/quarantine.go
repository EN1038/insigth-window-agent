package quarantine

import (
	"crypto/rand"
	"encoding/hex"
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

type Store struct {
	baseDir  string
	dir      string
	vault    string
	metaPath string // encrypted index (index.enc)
	legacy   string // old plaintext quarantine.dat
	items    []Metadata
}

type Metadata struct {
	ID           string `json:"id"`
	OriginalPath string `json:"original_path"`
	FileName     string `json:"file_name"`
	ThreatType   string `json:"threat_type"`
	IsolatedUnix int64  `json:"isolated_unix"`
	EncFile      string `json:"enc_file"` // relative name under Quarantine/
}

type metaFile struct {
	Version int        `json:"version"`
	Items   []Metadata `json:"items"`
}

func New(baseDir, quarantinePath string) *Store {
	paths := config.ResolvePaths(baseDir)
	if quarantinePath == "" {
		quarantinePath = filepath.Join(baseDir, "Quarantine")
	}
	return &Store{
		baseDir:  baseDir,
		dir:      quarantinePath,
		vault:    paths.VaultPath,
		metaPath: filepath.Join(quarantinePath, "index.enc"),
		legacy:   filepath.Join(quarantinePath, "quarantine.dat"),
	}
}

func (s *Store) encMeta() storage.EncryptedJSON {
	return storage.EncryptedJSON{
		VaultPath: s.vault,
		Path:      s.metaPath,
		Purpose:   "quarantine-meta",
		AAD:       "quarantine-meta|v1",
	}
}

func (s *Store) fileKey() ([]byte, error) {
	kek, err := keystore.EnsureKEK(s.vault)
	if err != nil {
		return nil, err
	}
	return crypto.DeriveSubkey(kek, "quarantine-file")
}

func (s *Store) Load() error {
	_ = os.MkdirAll(s.dir, 0o700)
	s.items = nil

	var mf metaFile
	err := s.encMeta().Load(&mf)
	if err == nil {
		s.items = mf.Items
		return nil
	}
	if _, statErr := os.Stat(s.metaPath); statErr == nil {
		// Encrypted index exists but cannot be opened — do not silently wipe it.
		return err
	}
	return s.migrateLegacy()
}

func (s *Store) Save() error {
	return s.encMeta().Save(metaFile{Version: 1, Items: s.items})
}

func (s *Store) migrateLegacy() error {
	b, err := os.ReadFile(s.legacy)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	key, err := s.fileKey()
	if err != nil {
		return err
	}
	var migrated []Metadata
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
		id := parts[0]
		m := Metadata{
			ID:           id,
			OriginalPath: parts[1],
			FileName:     parts[2],
			ThreatType:   parts[3],
			IsolatedUnix: ticks,
			EncFile:      id + ".qenc",
		}
		plainPath := filepath.Join(s.dir, id+".qfile")
		encPath := filepath.Join(s.dir, m.EncFile)
		if _, err := os.Stat(encPath); err == nil {
			migrated = append(migrated, m)
			_ = securefs.WipeAndRemove(plainPath)
			continue
		}
		if plain, err := os.ReadFile(plainPath); err == nil {
			aad := []byte("quarantine-file|v1|" + id)
			if err := crypto.WriteSealedFile(encPath, key, aad, plain); err != nil {
				return err
			}
			_ = securefs.WipeAndRemove(plainPath)
			migrated = append(migrated, m)
			continue
		}
		// Metadata without file — keep entry so UI still lists it.
		migrated = append(migrated, m)
	}
	s.items = migrated
	if err := s.Save(); err != nil {
		return err
	}
	_ = securefs.WipeAndRemove(s.legacy)
	return nil
}

func (s *Store) Isolate(filePath, threatType string) bool {
	if _, err := os.Stat(filePath); err != nil {
		return false
	}
	_ = os.MkdirAll(s.dir, 0o700)
	_ = s.Load()

	id := randomID()
	encName := id + ".qenc"
	dest := filepath.Join(s.dir, encName)

	key, err := s.fileKey()
	if err != nil {
		return false
	}
	in, err := os.Open(filePath)
	if err != nil {
		return false
	}
	aad := []byte("quarantine-file|v1|" + id)
	sealErr := crypto.SealReaderToFile(dest, key, aad, in)
	_ = in.Close()
	if sealErr != nil {
		_ = os.Remove(dest)
		return false
	}

	// Securely remove the original threat sample from its path.
	if err := securefs.WipeAndRemove(filePath); err != nil {
		// Fall back to plain delete if wipe fails (e.g. locked briefly).
		if err2 := os.Remove(filePath); err2 != nil {
			_ = securefs.WipeAndRemove(dest)
			return false
		}
	}

	s.items = append(s.items, Metadata{
		ID:           id,
		OriginalPath: filePath,
		FileName:     filepath.Base(filePath),
		ThreatType:   threatType,
		IsolatedUnix: time.Now().Unix(),
		EncFile:      encName,
	})
	if err := s.Save(); err != nil {
		return false
	}
	return true
}

// ReadSample decrypts a quarantined sample by id (for restore/export tooling).
func (s *Store) ReadSample(id string) ([]byte, error) {
	_ = s.Load()
	var m *Metadata
	for i := range s.items {
		if s.items[i].ID == id {
			m = &s.items[i]
			break
		}
	}
	if m == nil {
		return nil, fmt.Errorf("quarantine id not found")
	}
	name := m.EncFile
	if name == "" {
		name = m.ID + ".qenc"
	}
	key, err := s.fileKey()
	if err != nil {
		return nil, err
	}
	aad := []byte("quarantine-file|v1|" + m.ID)
	return crypto.ReadSealedFile(filepath.Join(s.dir, name), key, aad)
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
