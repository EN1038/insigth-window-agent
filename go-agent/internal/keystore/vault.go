package keystore

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureKEK loads an existing DPAPI-protected KEK from vaultPath,
// or creates a new random 32-byte KEK and stores it protected.
func EnsureKEK(vaultPath string) ([]byte, error) {
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

