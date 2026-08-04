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
	for _, dir := range w.watchDirs() {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return nil
			}
			_ = fsw.Add(path)
			return nil
		})
	}
	w.fs = fsw
	w.enabled = true
	go w.loop()
	return nil
}

func (w *Watcher) loop() {
	debounce := map[string]time.Time{}
	for {
		select {
		case ev, ok := <-w.fs.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
				continue
			}
			path := ev.Name
			if ev.Op&fsnotify.Rename != 0 && ev.Name != "" {
				path = ev.Name
			}
			w.handle(path, debounce)
		case _, ok := <-w.fs.Errors:
			if !ok {
				return
			}
		}
	}
}

func (w *Watcher) handle(filePath string, debounce map[string]time.Time) {
	if !w.settings.GetBool(settings.KeyRealtimeShield) {
		return
	}
	st, err := os.Stat(filePath)
	if err != nil || st.IsDir() {
		return
	}
	if !w.shouldScanPath(filePath) {
		return
	}
	if strings.Contains(strings.ToLower(filePath), `\data\`) {
		return
	}
	now := time.Now()
	if last, ok := debounce[filePath]; ok && now.Sub(last) < 2*time.Second {
		return
	}
	debounce[filePath] = now
	w.manager.StartSilentScan(filePath)
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
	profile := os.Getenv("USERPROFILE")
	dirs := []string{}
	if profile != "" {
		dirs = append(dirs, filepath.Join(profile, "Downloads"))
	}
	if desktop := os.Getenv("USERPROFILE"); desktop != "" {
		dirs = append(dirs, filepath.Join(desktop, "Desktop"))
	}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return out
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
