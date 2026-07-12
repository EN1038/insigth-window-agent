//go:build !windows

package securefs

func RestrictDirToSystemAndAdmins(dir string) error { return nil }

func RestrictEngineYara(baseDir string) error { return nil }
