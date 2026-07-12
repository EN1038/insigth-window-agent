package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/crypto"
	"github.com/sosecure/insite-agent/internal/keystore"
)

type EncryptedJSON struct {
	VaultPath string
	Path      string
	Purpose   string // used for HKDF subkey
	AAD       string // authenticated context string
}

func (e EncryptedJSON) Load(out any) error {
	b, err := os.ReadFile(e.Path)
	if err != nil {
		return err
	}
	env, err := crypto.Unmarshal(b)
	if err != nil {
		return err
	}
	kek, err := keystore.EnsureKEK(e.VaultPath)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveSubkey(kek, e.Purpose)
	if err != nil {
		return err
	}
	pt, err := crypto.OpenAESGCM(key, env, []byte(e.AAD))
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, out)
}

func (e EncryptedJSON) Save(in any) error {
	j, err := json.Marshal(in)
	if err != nil {
		return err
	}
	kek, err := keystore.EnsureKEK(e.VaultPath)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveSubkey(kek, e.Purpose)
	if err != nil {
		return err
	}
	env, err := crypto.SealAESGCM(key, j, []byte(e.AAD))
	if err != nil {
		return err
	}
	out, err := crypto.Marshal(env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.Path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	return os.WriteFile(e.Path, out, 0o600)
}

