package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

// Copies an external signatures.db into go-agent/bundled/ssdeep/ for dev/install,
// or seals directly into the agent data dir (encrypted shards).
//
// Usage:
//
//	ssdeep-bundled -src "C:\path\signatures.db"
//	ssdeep-bundled -src "C:\path\signatures.db" -seal
func main() {
	src := ""
	seal := false
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-src":
			if i+1 < len(os.Args) {
				i++
				src = os.Args[i]
			}
		case "-seal":
			seal = true
		}
	}
	if src == "" {
		fmt.Fprintln(os.Stderr, "usage: ssdeep-bundled -src <signatures.db> [-seal]")
		os.Exit(1)
	}
	if st, err := os.Stat(src); err != nil || st.IsDir() {
		fmt.Fprintln(os.Stderr, "invalid -src:", err)
		os.Exit(1)
	}

	exeDir := config.InstallDir()
	bundleDir := filepath.Join(exeDir, "bundled", "ssdeep")
	if wd, err := os.Getwd(); err == nil {
		for _, base := range []string{wd, filepath.Dir(wd)} {
			candidate := filepath.Join(base, "bundled", "ssdeep")
			if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
				bundleDir = candidate
				break
			}
		}
	}
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dst := filepath.Join(bundleDir, ssdeepscan.BundledSQLiteName)
	if err := copyFile(src, dst); err != nil {
		fmt.Fprintln(os.Stderr, "copy:", err)
		os.Exit(1)
	}
	fmt.Println("bundled:", dst)

	if !seal {
		return
	}
	base := config.DataBaseDir()
	n, err := ssdeepscan.SealBundledSignatures(base, config.InstallDir())
	if err != nil {
		fmt.Fprintln(os.Stderr, "seal:", err)
		os.Exit(1)
	}
	fmt.Printf("sealed %d signatures into %s\n", n, filepath.Join(base, "Data", "ssdeep"))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, dst)
}
