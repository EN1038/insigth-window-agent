package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteScanListUTF16NoBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	files := []string{`C:\Users\Public\sample_01.com`, `C:\Users\Public\sample_02.txt`}
	if err := writeScanListUTF16(path, files); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 4 {
		t.Fatalf("list too short: %d", len(b))
	}
	// Must not start with UTF-16 LE BOM — yara64 treats BOM as path garbage.
	if b[0] == 0xFF && b[1] == 0xFE {
		t.Fatal("scan-list must not include UTF-16 BOM")
	}
	// First path char 'C' as UTF-16LE = 0x43 0x00
	if b[0] != 'C' || b[1] != 0x00 {
		t.Fatalf("expected UTF-16LE path starting with C, got %02x %02x", b[0], b[1])
	}
}
