package crypto

import (
	"bytes"
	"testing"
)

func TestSealFileAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	aad := []byte("quarantine-file|v1|testid")
	plain := []byte("malware-sample-bytes-\x00\x01\xff")

	blob, err := SealFileAESGCM(key, aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OpenFileAESGCM(key, aad, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("mismatch: %q vs %q", out, plain)
	}
	if _, err := OpenFileAESGCM(key, []byte("wrong-aad"), blob); err == nil {
		t.Fatal("expected aad mismatch")
	}
}
