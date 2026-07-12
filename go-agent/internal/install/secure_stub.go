//go:build !windows

package install

func SecureLocalData(dataDir, installDir string) error { return nil }
