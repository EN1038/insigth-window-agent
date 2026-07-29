package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

var (
	siteKeyMu     sync.RWMutex
	activeSiteKey string
)

// SetActiveSiteKey configures the preferred KEK material (Center site_key / public_key).
func SetActiveSiteKey(siteKey string) {
	siteKeyMu.Lock()
	defer siteKeyMu.Unlock()
	activeSiteKey = strings.TrimSpace(siteKey)
}

func ActiveSiteKey() string {
	siteKeyMu.RLock()
	defer siteKeyMu.RUnlock()
	return activeSiteKey
}

// EnsureKEK loads or creates a KEK. When an active site_key is set, derives KEK from it
// (plan: encrypt TI/settings with site_key). Otherwise uses a DPAPI-wrapped random vault key.
func EnsureKEK(vaultPath string) ([]byte, error) {
	if sk := ActiveSiteKey(); sk != "" {
		return ensureSiteKeyKEK(vaultPath, sk)
	}
	return ensureRandomVaultKEK(vaultPath)
}

func ensureSiteKeyKEK(vaultPath, siteKey string) ([]byte, error) {
	kek, err := DeriveKEKFromSiteKey(siteKey)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(vaultPath); err != nil {
		protected, perr := ProtectLocalMachine(kek)
		if perr == nil {
			_ = os.MkdirAll(filepath.Dir(vaultPath), 0o700)
			_ = os.WriteFile(vaultPath, protected, 0o600)
		}
	}
	return kek, nil
}

func ensureRandomVaultKEK(vaultPath string) ([]byte, error) {
	if b, err := os.ReadFile(vaultPath); err == nil && len(b) > 0 {
		return UnprotectLocalMachine(b)
	}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, err
	}
	protected, err := ProtectLocalMachine(kek)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir vault dir: %w", err)
	}
	if err := os.WriteFile(vaultPath, protected, 0o600); err != nil {
		return nil, err
	}
	return kek, nil
}

// DeriveKEKFromSiteKey derives a 32-byte master key from the Center site_key (public_key).
func DeriveKEKFromSiteKey(siteKey string) ([]byte, error) {
	siteKey = strings.TrimSpace(siteKey)
	if siteKey == "" {
		return nil, fmt.Errorf("empty site key")
	}
	h := hkdf.New(sha256.New, []byte(siteKey), []byte("insite-agent-sitekey-salt-v1"), []byte("insite-agent|site-key-v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}
