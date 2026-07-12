package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)


// Envelope is a simple authenticated encryption container.
// Ciphertext includes the GCM authentication tag (Seal output).
type Envelope struct {
	V   int    `json:"v"`
	Alg string `json:"alg"`
	AAD string `json:"aad_b64"`
	N   string `json:"nonce_b64"`
	CT  string `json:"ct_b64"`
}

func DeriveSubkey(masterKey []byte, purpose string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("masterKey must be 32 bytes")
	}
	h := hkdf.New(sha256.New, masterKey, nil, []byte("insite-agent|"+purpose))
	out := make([]byte, 32)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func SealAESGCM(key []byte, plaintext []byte, aad []byte) (*Envelope, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return &Envelope{
		V:   1,
		Alg: "AES-256-GCM",
		AAD: base64.StdEncoding.EncodeToString(aad),
		N:   base64.StdEncoding.EncodeToString(nonce),
		CT:  base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func OpenAESGCM(key []byte, env *Envelope, expectedAAD []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("missing envelope")
	}
	if env.V != 1 || env.Alg != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported envelope")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes")
	}

	aad, err := base64.StdEncoding.DecodeString(env.AAD)
	if err != nil {
		return nil, fmt.Errorf("bad aad: %w", err)
	}
	// Enforce AAD match to prevent swapping envelopes across contexts.
	if string(aad) != string(expectedAAD) {
		return nil, fmt.Errorf("aad mismatch")
	}

	nonce, err := base64.StdEncoding.DecodeString(env.N)
	if err != nil {
		return nil, fmt.Errorf("bad nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, fmt.Errorf("bad ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch")
	}

	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return pt, nil
}

func Marshal(env *Envelope) ([]byte, error) {
	return json.Marshal(env)
}

func Unmarshal(b []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

