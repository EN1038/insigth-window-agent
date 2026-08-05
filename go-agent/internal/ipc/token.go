package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/securefs"
	"github.com/sosecure/insite-agent/internal/storage"
)

const tokenHeader = "X-Insite-Token"

type tokenPayload struct {
	Token string `json:"token"`
}

// TokenFile is the legacy plaintext path (migrated away on first use).
func TokenFile(baseDir string) string {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = config.DataBaseDir()
	}
	return filepath.Join(baseDir, "Data", "ipc.token")
}

func tokenEncFile(baseDir string) string {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = config.DataBaseDir()
	}
	return filepath.Join(baseDir, "Data", "ipc.token.enc")
}

func tokenStore(baseDir string) storage.EncryptedJSON {
	paths := config.ResolvePaths(baseDir)
	return storage.EncryptedJSON{
		VaultPath: paths.VaultPath,
		Path:      tokenEncFile(baseDir),
		Purpose:   "ipc-token",
		AAD:       "ipc-token|v1",
	}
}

// EnsureLocalToken creates or loads a local IPC token stored encrypted at rest.
func EnsureLocalToken(baseDir string) (string, error) {
	enc := tokenStore(baseDir)
	var p tokenPayload
	if err := enc.Load(&p); err == nil {
		tok := strings.TrimSpace(p.Token)
		if tok != "" {
			return tok, nil
		}
	}

	// Migrate legacy plaintext ipc.token if present.
	if b, err := os.ReadFile(TokenFile(baseDir)); err == nil {
		tok := strings.TrimSpace(string(b))
		if tok != "" {
			if err := enc.Save(tokenPayload{Token: tok}); err != nil {
				return "", err
			}
			_ = securefs.WipeAndRemove(TokenFile(baseDir))
			return tok, nil
		}
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(tokenEncFile(baseDir)), 0o700); err != nil {
		return "", err
	}
	if err := enc.Save(tokenPayload{Token: tok}); err != nil {
		return "", err
	}
	_ = securefs.WipeAndRemove(TokenFile(baseDir))
	return tok, nil
}

// LoadLocalToken reads the encrypted token if present (falls back to legacy plaintext once).
func LoadLocalToken(baseDir string) (string, error) {
	var p tokenPayload
	if err := tokenStore(baseDir).Load(&p); err == nil {
		tok := strings.TrimSpace(p.Token)
		if tok != "" {
			return tok, nil
		}
	}
	b, err := os.ReadFile(TokenFile(baseDir))
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", os.ErrNotExist
	}
	// Opportunistic migrate for next start.
	_ = tokenStore(baseDir).Save(tokenPayload{Token: tok})
	_ = securefs.WipeAndRemove(TokenFile(baseDir))
	return tok, nil
}
