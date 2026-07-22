//go:build windows

package ui

import (
	"os"
	"path/filepath"
)

// prepareSoftwareGL forces Mesa llvmpipe when bundled opengl32.dll is present.
// This lets Fyne open a window on VMs / RDP / machines without hardware OpenGL.
// Must run before any Fyne/GLFW window is created.
func prepareSoftwareGL() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	mesaDLL := filepath.Join(dir, "opengl32.dll")
	if _, err := os.Stat(mesaDLL); err != nil {
		return
	}

	// Prefer software pipe so we do not depend on GPU / WGL ICD.
	_ = os.Setenv("GALLIUM_DRIVER", "llvmpipe")
	_ = os.Setenv("LIBGL_ALWAYS_SOFTWARE", "true")
	_ = os.Setenv("MESA_LOADER_DRIVER_OVERRIDE", "llvmpipe")

	// Windows private-DLL redirection (best-effort).
	localMarker := exe + ".local"
	if _, err := os.Stat(localMarker); err != nil {
		_ = os.WriteFile(localMarker, nil, 0o644)
	}
}
