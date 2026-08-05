package scan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/sosecure/insite-agent/internal/settings"
)

type Enumerator struct {
	settings   *settings.Store
	exclusions []string
	extensions map[string]struct{}
	scanAll    bool
	stop       bool

	OnDirectory func(string)
	OnFile      func(FileItem)
}

func NewEnumerator(st *settings.Store, scanAll bool, allExtensions bool) *Enumerator {
	e := &Enumerator{
		settings:   st,
		exclusions: st.Exclusions(),
		scanAll:    scanAll,
		extensions: map[string]struct{}{},
	}
	if !allExtensions {
		for _, ext := range st.ScanExtensions() {
			e.extensions[strings.ToLower(ext)] = struct{}{}
		}
	}
	return e
}

func (e *Enumerator) Stop() {
	e.stop = true
}

func (e *Enumerator) EnumerateQuick() {
	for _, p := range e.settings.QuickScanPaths() {
		if e.stop {
			return
		}
		if st, err := os.Stat(p); err == nil {
			if st.IsDir() {
				e.walkDir(p)
			} else {
				e.processFile(p)
			}
		}
	}
}

func (e *Enumerator) EnumerateAllFixedDrives() {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		if e.stop {
			return
		}
		root := string(drive) + `:\`
		if _, err := os.Stat(root); err != nil {
			continue
		}
		if getDriveType(root) != driveFixed {
			continue
		}
		e.walkDir(root)
	}
}

func (e *Enumerator) EnumeratePath(path string) {
	if e.stop {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if st.IsDir() {
		e.walkDir(path)
	} else {
		e.processFile(path)
	}
}

func (e *Enumerator) walkDir(path string) {
	if e.stop {
		return
	}
	if e.isExcluded(path) {
		return
	}
	if e.isReparsePoint(path) {
		return
	}
	if e.OnDirectory != nil {
		e.OnDirectory(path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if e.stop {
			return
		}
		full := filepath.Join(path, ent.Name())
		if ent.IsDir() {
			e.walkDir(full)
			continue
		}
		e.processFile(full)
	}
}

func (e *Enumerator) processFile(path string) {
	if e.stop {
		return
	}
	ext := strings.ToLower(filepath.Ext(path))
	if len(e.extensions) > 0 {
		if _, ok := e.extensions[ext]; !ok {
			return
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	if e.OnFile != nil {
		e.OnFile(FileItem{
			Path:          path,
			Size:          st.Size(),
			LastWriteUnix: st.ModTime().Unix(),
			CreateUnix:    st.ModTime().Unix(),
		})
	}
}

func (e *Enumerator) isExcluded(path string) bool {
	lower := strings.ToLower(path)
	for _, ex := range e.exclusions {
		if strings.Contains(lower, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

func (e *Enumerator) isReparsePoint(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

const (
	driveUnknown = 0
	driveFixed   = 3
)

func getDriveType(root string) uint32 {
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDriveTypeW")
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r)
}
