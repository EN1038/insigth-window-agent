package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Binary on-disk blob (no base64) for larger payloads such as quarantine samples.
// Layout: magic(4) | ver(u8)=1 | nonceLen(u8) | nonce | ctLen(u64 BE) | ciphertext
var fileBlobMagic = [4]byte{'I', 'A', 'E', '1'}

// SealFileAESGCM encrypts plaintext to a compact binary blob.
func SealFileAESGCM(key, aad, plaintext []byte) ([]byte, error) {
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

	out := make([]byte, 0, 4+1+1+len(nonce)+8+len(ct))
	out = append(out, fileBlobMagic[:]...)
	out = append(out, 1) // version
	out = append(out, byte(len(nonce)))
	out = append(out, nonce...)
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(ct)))
	out = append(out, lenBuf[:]...)
	out = append(out, ct...)
	return out, nil
}

// OpenFileAESGCM decrypts a blob produced by SealFileAESGCM.
func OpenFileAESGCM(key, aad, blob []byte) ([]byte, error) {
	if len(blob) < 4+1+1+8 {
		return nil, fmt.Errorf("blob too short")
	}
	if string(blob[:4]) != string(fileBlobMagic[:]) {
		return nil, fmt.Errorf("bad blob magic")
	}
	off := 4
	if blob[off] != 1 {
		return nil, fmt.Errorf("unsupported blob version %d", blob[off])
	}
	off++
	nLen := int(blob[off])
	off++
	if nLen <= 0 || off+nLen+8 > len(blob) {
		return nil, fmt.Errorf("bad nonce length")
	}
	nonce := blob[off : off+nLen]
	off += nLen
	ctLen := binary.BigEndian.Uint64(blob[off : off+8])
	off += 8
	if uint64(len(blob)-off) != ctLen {
		return nil, fmt.Errorf("ciphertext length mismatch")
	}
	ct := blob[off:]

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
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce size mismatch")
	}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return pt, nil
}

// WriteSealedFile encrypts plaintext and writes it to path (mode 0600).
func WriteSealedFile(path string, key, aad, plaintext []byte) error {
	blob, err := SealFileAESGCM(key, aad, plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

// ReadSealedFile reads and decrypts a sealed file from path.
func ReadSealedFile(path string, key, aad []byte) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenFileAESGCM(key, aad, blob)
}

// SealReaderToFile streams plaintext from r into an encrypted file.
// The full content is buffered (typical quarantine samples are small/medium).
func SealReaderToFile(path string, key, aad []byte, r io.Reader) error {
	plain, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return WriteSealedFile(path, key, aad, plain)
}
