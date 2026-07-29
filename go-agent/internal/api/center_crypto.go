package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// CenterAES mirrors PHP encrypt_decrypt() in app/Helpers/fn_custom.php:
//
//	$secret_key = 'secret-key-' . $public_key . $ip . $mac;
//	$secret_iv  = 'secret-iv-'  . $public_key . $ip . $mac;
//	$key = hash('sha256', $secret_key);           // hex string
//	$iv  = substr(hash('sha256', $secret_iv), 0, 16);
//	openssl_encrypt(..., AES-256-CBC, $key, 0, $iv) then base64_encode again
func CenterEncrypt(plaintext, publicKey, ipKey, macKey string) (string, error) {
	key, iv, err := centerAESKeyIV(publicKey, ipKey, macKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	// PHP options=0 → openssl returns base64, then outer base64_encode.
	inner := base64.StdEncoding.EncodeToString(ct)
	return base64.StdEncoding.EncodeToString([]byte(inner)), nil
}

func CenterDecrypt(ciphertext, publicKey, ipKey, macKey string) (string, error) {
	key, iv, err := centerAESKeyIV(publicKey, ipKey, macKey)
	if err != nil {
		return "", err
	}
	outer, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertext))
	if err != nil {
		return "", fmt.Errorf("outer base64: %w", err)
	}
	// Outer decode yields the openssl base64 string (or raw if already binary).
	inner := string(outer)
	raw, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		// Some payloads may already be raw ciphertext after one decode.
		raw = outer
	}
	if len(raw)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d not multiple of block size", len(raw))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pt := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, raw)
	unpadded, err := pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

func centerAESKeyIV(publicKey, ipKey, macKey string) (key, iv []byte, err error) {
	secretKey := "secret-key-" + publicKey + ipKey + macKey
	secretIV := "secret-iv-" + publicKey + ipKey + macKey
	keyHex := sha256Hex(secretKey)
	ivHex := sha256Hex(secretIV)
	// PHP passes the hex string to openssl; AES-256 uses first 32 bytes of that string.
	key = []byte(keyHex)[:32]
	iv = []byte(ivHex)[:16]
	return key, iv, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - (len(b) % blockSize)
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > blockSize || pad > len(b) {
		return nil, fmt.Errorf("invalid pkcs7 padding")
	}
	for i := len(b) - pad; i < len(b); i++ {
		if b[i] != byte(pad) {
			return nil, fmt.Errorf("invalid pkcs7 padding bytes")
		}
	}
	return b[:len(b)-pad], nil
}
