package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sosecure/insite-agent/internal/crypto"
	"github.com/sosecure/insite-agent/internal/keystore"
	"github.com/sosecure/insite-agent/internal/securefs"
)

// Load loads config from config.enc; if missing, it attempts to migrate legacy
// config.json (either plaintext JSON or legacy .NET machine-bound AES-CBC).
func Load(baseDir string) (*AgentConfig, error) {
	paths := ResolvePaths(baseDir)
	_ = os.MkdirAll(paths.ConfigDir, 0o700)
	_ = os.MkdirAll(paths.DataDir, 0o700)

	if cfg, err := loadEncrypted(paths); err == nil && cfg != nil {
		_ = wipeLegacyConfig(paths)
		return cfg, nil
	}

	// Try legacy config.json.
	cfg, legacyRaw, err := loadLegacy(paths.LegacyPath)
	if err != nil {
		return nil, err
	}

	// Persist into new encrypted format (best effort). Only remove the plaintext
	// fallback after we can read config.enc back successfully, so a broken/unreadable
	// config.enc (e.g. regenerated vault key) never leaves us with no config at all.
	if err := SaveEncrypted(paths, cfg); err == nil {
		if v, verr := loadEncrypted(paths); verr == nil && v != nil {
			_ = wipeLegacyConfig(paths)
		}
	}
	_ = legacyRaw
	return cfg, nil
}

func wipeLegacyConfig(paths Paths) error {
	if _, err := os.Stat(paths.ConfigPath); err != nil {
		return nil
	}
	if _, err := os.Stat(paths.LegacyPath); err != nil {
		return nil
	}
	return securefs.WipeAndRemove(paths.LegacyPath)
}

func Save(baseDir string, cfg *AgentConfig) error {
	paths := ResolvePaths(baseDir)
	_ = os.MkdirAll(paths.ConfigDir, 0o700)
	_ = os.MkdirAll(paths.DataDir, 0o700)
	return SaveEncrypted(paths, cfg)
}

func loadEncrypted(paths Paths) (*AgentConfig, error) {
	b, err := os.ReadFile(paths.ConfigPath)
	if err != nil {
		return nil, err
	}
	env, err := crypto.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	kek, err := keystore.EnsureKEK(paths.VaultPath)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveSubkey(kek, "config")
	if err != nil {
		return nil, err
	}
	aad := []byte("config|v1")
	pt, err := crypto.OpenAESGCM(key, env, aad)
	if err != nil {
		return nil, err
	}
	var cfg AgentConfig
	if err := json.Unmarshal(pt, &cfg); err != nil {
		return nil, err
	}
	if cfg.SiteIP == "" || cfg.SiteID == "" || cfg.SiteKey == "" {
		return nil, fmt.Errorf("config missing required fields")
	}
	return &cfg, nil
}

func SaveEncrypted(paths Paths, cfg *AgentConfig) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if cfg.SiteIP == "" || cfg.SiteID == "" || cfg.SiteKey == "" {
		return fmt.Errorf("config missing required fields")
	}
	j, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	kek, err := keystore.EnsureKEK(paths.VaultPath)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveSubkey(kek, "config")
	if err != nil {
		return err
	}
	aad := []byte("config|v1")
	env, err := crypto.SealAESGCM(key, j, aad)
	if err != nil {
		return err
	}
	out, err := crypto.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(paths.ConfigPath, out, 0o600)
}

// loadLegacy reads legacy config.json. It supports:
// - Plain JSON
// - Legacy .NET encrypted Base64: IV(16) + ciphertext, AES-256-CBC with key = SHA256("SOSECURE_AGENT_"+MachineName+"_CONFIG_KEY_2024")
func loadLegacy(path string) (*AgentConfig, string, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	raw := strings.TrimSpace(string(rawBytes))

	// Plain JSON detection
	if strings.HasPrefix(raw, "{") {
		var cfg AgentConfig
		if err := json.Unmarshal(rawBytes, &cfg); err != nil {
			return nil, raw, err
		}
		return &cfg, raw, validateLegacy(&cfg)
	}

	// Encrypted base64
	plain, err := decryptLegacyDotNet(raw)
	if err != nil {
		return nil, raw, err
	}
	var cfg AgentConfig
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, raw, err
	}
	return &cfg, raw, validateLegacy(&cfg)
}

func validateLegacy(cfg *AgentConfig) error {
	if cfg == nil || cfg.SiteIP == "" || cfg.SiteID == "" || cfg.SiteKey == "" {
		return fmt.Errorf("legacy config missing required fields")
	}
	return nil
}

func decryptLegacyDotNet(b64 string) ([]byte, error) {
	full, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(full) < 16+16 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := full[:16]
	ct := full[16:]

	machine := os.Getenv("COMPUTERNAME")
	if machine == "" {
		machine = "UNKNOWN"
	}
	rawKey := "SOSECURE_AGENT_" + machine + "_CONFIG_KEY_2024"
	key := sha256.Sum256([]byte(rawKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)

	// PKCS7 unpad
	if len(pt) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(pt[len(pt)-1])
	if pad <= 0 || pad > aes.BlockSize || pad > len(pt) {
		return nil, fmt.Errorf("bad padding")
	}
	for i := 0; i < pad; i++ {
		if pt[len(pt)-1-i] != byte(pad) {
			return nil, fmt.Errorf("bad padding")
		}
	}
	return pt[:len(pt)-pad], nil
}

