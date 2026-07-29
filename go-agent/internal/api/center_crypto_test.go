package api

import (
	"testing"
)

func TestCenterEncryptDecryptRoundTrip(t *testing.T) {
	pub := "test-public-key-abc"
	ip := "192.168.1.10"
	mac := "aa:bb:cc:dd:ee:ff"
	plain := `{"error":"","status_code":200,"data":{"ok":true}}`

	enc, err := CenterEncrypt(plain, pub, ip, mac)
	if err != nil {
		t.Fatal(err)
	}
	if enc == "" || enc == plain {
		t.Fatalf("expected ciphertext, got %q", enc)
	}
	dec, err := CenterDecrypt(enc, pub, ip, mac)
	if err != nil {
		t.Fatal(err)
	}
	if dec != plain {
		t.Fatalf("round-trip mismatch:\n got %s\nwant %s", dec, plain)
	}
}
