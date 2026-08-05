//go:build windows

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
)

type Watcher struct {
	manager  *scan.Manager
	settings *settings.Store
	fs       *fsnotify.Watcher
	mu       sync.Mutex
	enabled  bool
}

func New(manager *scan.Manager, st *settings.Store) *Watcher {
	return &Watcher{manager: manager, settings: st}
}

func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	w.syncEnabled()
	for {
		select {
		case <-ctx.Done():
			w.stop()
			return
		case <-t.C:
			w.syncEnabled()
		}
	}
}

func (w *Watcher) syncEnabled() {
	want := w.settings.GetBool(settings.KeyRealtimeShield)
	w.mu.Lock()
	defer w.mu.Unlock()
	if want && !w.enabled {
		_ = w.startLocked()
	} else if !want && w.enabled {
		w.stopLocked()
	}
}

func (w *Watcher) startLocked() error {
	if w.enabled {
		return nil
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	added := 0
	var hitCap bool
	for _, dir := range w.watchDirs() {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if hitCap {
				return filepath.SkipDir
			}
			if err != nil || info == nil || !info.IsDir() {
				return nil
			}
			if shouldSkipRealtimeDir(path) {
				return filepath.SkipDir
			}
			if fsw.Add(path) == nil {
				added++
			}
			// Cap watch fan-out so huge Document trees do not exhaust handles.
			if added >= 12000 {
				hitCap = true
				return filepath.SkipDir
			}
			return nil
		})
		if hitCap {
			break
		}
	}
	if added == 0 {
		_ = fsw.Close()
		return nil
	}
	w.fs = fsw
	w.enabled = true
	// Pass local fsw so stop can Close without racing loop on w.fs nil.
	go w.loop(fsw)
	return nil
}

func (w *Watcher) loop(fsw *fsnotify.Watcher) {
	debounce := map[string]time.Time{}
	for {
		select {
		case ev, ok := <-fsw.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
				continue
			}
			w.handle(ev.Name, ev.Op, debounce)
		case _, ok := <-fsw.Errors:
			if !ok {
				return
			}
		}
	}
}

func (w *Watcher) handle(filePath string, op fsnotify.Op, debounce map[string]time.Time) {
	if !w.settings.GetBool(settings.KeyRealtimeShield) {
		return
	}
	if isHardExcludedPath(filePath) {
		return
	}
	st, err := os.Stat(filePath)
	if err != nil {
		return
	}
	if st.IsDir() {
		// Watch newly created subdirectories (fsnotify is not recursive).
		if op&fsnotify.Create != 0 && !shouldSkipRealtimeDir(filePath) {
			w.mu.Lock()
			if w.fs != nil {
				_ = w.fs.Add(filePath)
			}
			w.mu.Unlock()
		}
		return
	}
	if !w.shouldScanPath(filePath) {
		return
	}
	lower := strings.ToLower(filePath)
	if strings.Contains(lower, `\data\`) || strings.Contains(lower, `\quarantine\`) {
		return
	}
	now := time.Now()
	if last, ok := debounce[filePath]; ok && now.Sub(last) < 2*time.Second {
		return
	}
	debounce[filePath] = now
	if len(debounce) > 4000 {
		for k, t := range debounce {
			if now.Sub(t) > time.Minute {
				delete(debounce, k)
			}
		}
	}
	_ = w.manager.StartSilentScan(filePath)
}

// shouldScanPath mirrors on-demand ScanExtensions so realtime and custom scan
// agree. Always skip engine temp / rule artifacts.
func (w *Watcher) shouldScanPath(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" || ext == ".tmp" || ext == ".yar" {
		return false
	}
	allowed := w.settings.ScanExtensions()
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == ext {
			return true
		}
	}
	return false
}

func (w *Watcher) watchDirs() []string {
	if w.settings != nil {
		return w.settings.RealtimeWatchRoots()
	}
	return nil
}

func shouldSkipRealtimeDir(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "node_modules", ".git", ".svn", ".hg", "cache", "caches", "code cache",
		"gpuCache", "gpucache", "shadercache", "iNet Cache", "inetcache",
		"windows", "winsxs", "softwaredistribution", "system volume information",
		"$recycle.bin", "quarantine":
		return true
	}
	return isHardExcludedPath(path)
}

func isHardExcludedPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ex := range settings.HardExclusions() {
		if strings.Contains(lower, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

func (w *Watcher) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopLocked()
}

func (w *Watcher) stopLocked() {
	if w.fs != nil {
		_ = w.fs.Close()
		w.fs = nil
	}
	w.enabled = false
}
