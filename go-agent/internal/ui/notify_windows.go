//go:build windows

package ui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/wintoast"
)

type notifyItem struct {
	Key     string
	Time    string
	Message string
}

type notifyBell struct {
	widget.BaseWidget
	router     *Router
	icon       *canvas.Image
	badge      *canvas.Text
	badgeBg    *canvas.Rectangle
	offsetY    float32
	unread     int
	bounce     int
	popup      *widget.PopUp
	mu         sync.Mutex
	seenKeys   map[string]bool
	dismissed  map[string]bool
	items      []notifyItem
	warmed     bool // first history poll only seeds mailbox; no tray toasts
}

func newNotifyBell(r *Router) *notifyBell {
	n := &notifyBell{
		router:    r,
		icon:      canvas.NewImageFromResource(theme.MailComposeIcon()),
		badge:     canvas.NewText("", colorOnAccent),
		badgeBg:   canvas.NewRectangle(colorError),
		seenKeys:  map[string]bool{},
		dismissed: map[string]bool{},
		items:     nil,
	}
	n.icon.FillMode = canvas.ImageFillContain
	n.icon.SetMinSize(fyne.NewSize(18, 18))
	n.badge.TextSize = 9
	n.badge.TextStyle = fyne.TextStyle{Bold: true}
	n.badge.Alignment = fyne.TextAlignCenter
	n.badgeBg.CornerRadius = 8
	n.ExtendBaseWidget(n)
	n.refreshBadge()
	return n
}

func (n *notifyBell) CreateRenderer() fyne.WidgetRenderer {
	return &notifyBellRenderer{n: n, objects: []fyne.CanvasObject{n.icon, n.badgeBg, n.badge}}
}

type notifyBellRenderer struct {
	n       *notifyBell
	objects []fyne.CanvasObject
}

func (r *notifyBellRenderer) Layout(size fyne.Size) {
	iconSz := float32(18)
	r.n.icon.Resize(fyne.NewSize(iconSz, iconSz))
	r.n.icon.Move(fyne.NewPos((size.Width-iconSz)/2, (size.Height-iconSz)/2+r.n.offsetY))
	badgeSz := float32(14)
	r.n.badgeBg.Resize(fyne.NewSize(badgeSz, badgeSz))
	r.n.badgeBg.Move(fyne.NewPos(size.Width-badgeSz-1, 1))
	r.n.badge.Resize(fyne.NewSize(badgeSz, badgeSz))
	r.n.badge.Move(fyne.NewPos(size.Width-badgeSz-1, 1))
}

func (r *notifyBellRenderer) MinSize() fyne.Size { return fyne.NewSize(28, 28) }
func (r *notifyBellRenderer) Refresh() {
	r.n.refreshBadge()
	canvas.Refresh(r.n)
}
func (r *notifyBellRenderer) Objects() []fyne.CanvasObject { return r.objects }
func (r *notifyBellRenderer) Destroy()                    {}

func (n *notifyBell) refreshBadge() {
	n.mu.Lock()
	u := n.unread
	n.mu.Unlock()
	if u <= 0 {
		n.badge.Hide()
		n.badgeBg.Hide()
		return
	}
	txt := strconv.Itoa(u)
	if u > 9 {
		txt = "9+"
	}
	n.badge.Text = txt
	n.badge.Show()
	n.badgeBg.Show()
}

func (n *notifyBell) Tapped(*fyne.PointEvent) {
	n.showDropdown()
}

func (n *notifyBell) Cursor() desktop.Cursor {
	return desktop.PointerCursor
}

func (n *notifyBell) removeItem(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dismissed[key] = true
	out := n.items[:0]
	for _, it := range n.items {
		if it.Key == key {
			continue
		}
		out = append(out, it)
	}
	n.items = out
}

func (n *notifyBell) clearAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, it := range n.items {
		n.dismissed[it.Key] = true
	}
	n.items = nil
	n.unread = 0
}

func (n *notifyBell) showDropdown() {
	n.mu.Lock()
	items := append([]notifyItem(nil), n.items...)
	n.unread = 0
	n.mu.Unlock()
	n.refreshBadge()
	n.Refresh()

	title := canvas.NewText("Mailbox", colorText)
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.TextSize = 14

	clearBtn := widget.NewButtonWithIcon("Clear all", theme.DeleteIcon(), func() {
		n.clearAll()
		n.refreshBadge()
		n.Refresh()
		n.showDropdown()
	})
	clearBtn.Importance = widget.LowImportance
	if len(items) == 0 {
		clearBtn.Disable()
	}

	header := container.NewBorder(nil, nil, title, clearBtn)
	rows := []fyne.CanvasObject{header, divider()}

	if len(items) == 0 {
		empty := widget.NewLabel("No messages yet.\nUpdates from sync, scans, and agent upgrades will appear here.")
		empty.Wrapping = fyne.TextWrapWord
		empty.Importance = widget.LowImportance
		rows = append(rows, empty)
	} else {
		for _, it := range items {
			item := it
			t := formatNotifyTime(item.Time)
			timeLbl := canvasMuted(t, colorMuted)

			msg := widget.NewLabel(item.Message)
			msg.Wrapping = fyne.TextWrapWord
			msg.TextStyle = fyne.TextStyle{}

			del := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
				n.removeItem(item.Key)
				n.refreshBadge()
				n.Refresh()
				n.showDropdown()
			})
			del.Importance = widget.LowImportance

			body := container.NewBorder(nil, nil, nil, del, container.NewVBox(timeLbl, msg))
			rows = append(rows, body, divider())
		}
	}

	box := container.NewVBox(rows...)
	scroll := container.NewVScroll(box)
	const popupW, popupH float32 = 380, 320
	scroll.SetMinSize(fyne.NewSize(popupW-16, popupH-16))
	padded := container.NewPadded(scroll)

	if n.popup != nil {
		n.popup.Hide()
	}
	n.popup = widget.NewPopUp(padded, n.router.window.Canvas())
	n.popup.Resize(fyne.NewSize(popupW, popupH))

	abs := fyne.CurrentApp().Driver().AbsolutePositionForObject(n)
	can := n.router.window.Canvas().Size()
	x := abs.X + n.Size().Width - popupW
	y := abs.Y + n.Size().Height + 6
	if x < 8 {
		x = 8
	}
	if y < 8 {
		y = 8
	}
	if can.Width > 0 && x+popupW > can.Width-8 {
		x = can.Width - popupW - 8
	}
	if can.Height > 0 && y+popupH > can.Height-8 {
		y = abs.Y - popupH - 6
		if y < 8 {
			y = 8
		}
	}
	n.popup.ShowAtPosition(fyne.NewPos(x, y))
}

func formatNotifyTime(t string) string {
	t = strings.TrimSpace(t)
	if len(t) > 19 {
		t = t[:19]
	}
	return strings.ReplaceAll(t, "T", " ")
}

var (
	reSyncedRules = regexp.MustCompile(`(?i)^synced rules=(\d+)\s*ssdeep=(\d+)$`)
	reSyncDone    = regexp.MustCompile(`(?i)^sync done \(rules=(\d+)\s*ssdeep=(\d+)\)$`)
	reScanNotify  = regexp.MustCompile(`(?i)^scan (\w+)\s*[—\-]+\s*scanned (\d+),\s*skipped (\d+),\s*threats (\d+)$`)
	reScanShort   = regexp.MustCompile(`(?i)^scan (\w+)\s*[—\-]+\s*(\d+) scanned,\s*(\d+) threats$`)
	reUpdateAvail = regexp.MustCompile(`(?i)^update available\s+(.+)$`)
	reYaraDone    = regexp.MustCompile(`(?i)^yara rules done \((\d+) ok,\s*(\d+) failed\)$`)
	reSsdeepProg  = regexp.MustCompile(`(?i)^ssdeep\s+(\d+)/(\d+):\s*(.+)$`)
	reYaraProg    = regexp.MustCompile(`(?i)^yara rules\s+(\d+)/(\d+):\s*(.+)$`)
)

// humanizeNotifyMessage rewrites legacy cryptic notify text for the mailbox.
func humanizeNotifyMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return msg
	}
	if m := reSyncedRules.FindStringSubmatch(msg); len(m) == 3 {
		return humanizeTICounts(atoiSafe(m[1]), atoiSafe(m[2]))
	}
	if m := reSyncDone.FindStringSubmatch(msg); len(m) == 3 {
		return humanizeTICounts(atoiSafe(m[1]), atoiSafe(m[2]))
	}
	if m := reScanNotify.FindStringSubmatch(msg); len(m) == 5 {
		status, scanned, skipped, threats := m[1], atoiSafe(m[2]), atoiSafe(m[3]), atoiSafe(m[4])
		switch strings.ToLower(status) {
		case "completed":
			if threats > 0 {
				return fmt.Sprintf("Scan finished. Checked %d file(s), skipped %d, found %d threat(s).", scanned, skipped, threats)
			}
			return fmt.Sprintf("Scan finished. Checked %d file(s), skipped %d. No threats found.", scanned, skipped)
		case "stopped":
			return fmt.Sprintf("Scan stopped early. Checked %d file(s), skipped %d, found %d threat(s).", scanned, skipped, threats)
		}
	}
	if m := reScanShort.FindStringSubmatch(msg); len(m) == 4 {
		status, scanned, threats := m[1], atoiSafe(m[2]), atoiSafe(m[3])
		if strings.EqualFold(status, "completed") {
			if threats > 0 {
				return fmt.Sprintf("Scan finished. Checked %d file(s), found %d threat(s).", scanned, threats)
			}
			return fmt.Sprintf("Scan finished. Checked %d file(s). No threats found.", scanned)
		}
		return fmt.Sprintf("Scan %s. Checked %d file(s), found %d threat(s).", status, scanned, threats)
	}
	if m := reUpdateAvail.FindStringSubmatch(msg); len(m) == 2 {
		return fmt.Sprintf("A new agent version (%s) is available from Center.", strings.TrimSpace(m[1]))
	}
	if m := reYaraDone.FindStringSubmatch(msg); len(m) == 3 {
		okN, failN := atoiSafe(m[1]), atoiSafe(m[2])
		if failN > 0 && okN == 0 {
			return fmt.Sprintf("Could not download YARA rule packs (%d failed). Local rules were kept when possible.", failN)
		}
		if failN > 0 {
			return fmt.Sprintf("Downloaded %d YARA rule pack(s); %d pack(s) could not be downloaded.", okN, failN)
		}
		return fmt.Sprintf("Downloaded %d YARA rule pack(s).", okN)
	}
	if m := reYaraProg.FindStringSubmatch(msg); len(m) == 4 {
		return fmt.Sprintf("Downloading YARA rules (%s of %s): %s", m[1], m[2], m[3])
	}
	if m := reSsdeepProg.FindStringSubmatch(msg); len(m) == 4 {
		return fmt.Sprintf("Downloading ssdeep signatures (%s of %s): %s", m[1], m[2], m[3])
	}
	low := strings.ToLower(msg)
	switch {
	case strings.EqualFold(msg, "Settings updated from Center"):
		return "Protection settings were updated from Center."
	case strings.Contains(low, "sync queued") || strings.Contains(low, "waiting for scan to finish"):
		return "Threat intelligence update is waiting until the current scan finishes."
	case strings.HasPrefix(low, "yara rules ready"):
		return "YARA detection rules are ready."
	case strings.HasPrefix(low, "ssdeep already") || strings.HasPrefix(low, "ssdeep ready") || strings.HasPrefix(low, "ssdeep categorized"):
		return "Fuzzy (ssdeep) signatures are ready."
	case strings.HasPrefix(low, "no ssdeep packs"):
		return "No new ssdeep signature packs to download."
	case strings.HasPrefix(low, "waiting for ssdeep"):
		return "Waiting for ssdeep signature packs from Center…"
	case strings.HasPrefix(low, "waiting for yara"):
		return "Waiting for YARA rule packs from Center…"
	case low == "starting sync…" || low == "starting sync...":
		return "Starting threat intelligence sync…"
	case strings.Contains(low, "syncing threat intelligence"):
		return "Syncing threat intelligence from Center…"
	}
	return msg
}

func humanizeTICounts(rulesN, ssdeepN int) string {
	switch {
	case rulesN <= 0 && ssdeepN <= 0:
		return "Threat intelligence is up to date. No new detection rules or fuzzy signatures were needed."
	case rulesN > 0 && ssdeepN > 0:
		return fmt.Sprintf("Threat intelligence updated. Downloaded %d YARA rule file(s) and %d ssdeep signature pack(s).", rulesN, ssdeepN)
	case rulesN > 0:
		return fmt.Sprintf("Threat intelligence updated. Downloaded %d YARA rule file(s). Fuzzy signatures were already current.", rulesN)
	default:
		return fmt.Sprintf("Threat intelligence updated. Downloaded %d ssdeep signature pack(s). YARA rules were already current.", ssdeepN)
	}
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func (n *notifyBell) ingest(events []ipc.HistoryEvent) {
	added := 0
	var toastMsgs []string
	n.mu.Lock()
	warmed := n.warmed
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind != "ui.notify" {
			continue
		}
		key := e.Time + "|" + e.Message
		if n.dismissed[key] {
			n.seenKeys[key] = true
			continue
		}
		if n.seenKeys[key] {
			continue
		}
		n.seenKeys[key] = true
		msg := humanizeNotifyMessage(e.Message)
		n.items = append([]notifyItem{{
			Key:     key,
			Time:    e.Time,
			Message: msg,
		}}, n.items...)
		if len(n.items) > 30 {
			n.items = n.items[:30]
		}
		n.unread++
		added++
		if warmed && shouldTrayToast(msg) {
			toastMsgs = append(toastMsgs, msg)
		}
	}
	n.warmed = true
	n.mu.Unlock()
	if added > 0 {
		n.startBounce()
	}
	fyne.Do(func() {
		n.refreshBadge()
		n.Refresh()
	})
	if len(toastMsgs) == 0 {
		return
	}
	// Toast only while the main window is hidden in the tray.
	if n.router == nil || !n.router.isWindowHidden() {
		return
	}
	go func(msgs []string) {
		for _, msg := range msgs {
			title := trayToastTitle(msg)
			_ = wintoast.Notify(title, msg)
		}
	}(toastMsgs)
}

// shouldTrayToast skips noisy in-progress sync lines; mailbox still keeps them.
func shouldTrayToast(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	if low == "" {
		return false
	}
	switch {
	case strings.HasPrefix(low, "downloading yara"),
		strings.HasPrefix(low, "downloading ssdeep"),
		strings.HasPrefix(low, "starting threat intelligence"),
		strings.HasPrefix(low, "syncing threat intelligence"),
		strings.HasPrefix(low, "waiting for"):
		return false
	}
	return true
}

func trayToastTitle(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "scan finished"), strings.Contains(low, "scan stopped"):
		if strings.Contains(low, "threat") && !strings.Contains(low, "no threats") {
			return "Threat detected"
		}
		return "Scan complete"
	case strings.Contains(low, "threat intelligence"),
		strings.Contains(low, "protection settings"),
		strings.Contains(low, "yara"),
		strings.Contains(low, "ssdeep"),
		strings.Contains(low, "fuzzy"):
		return "Threat intelligence"
	case strings.Contains(low, "agent version"), strings.Contains(low, "update"):
		return "Agent update"
	case strings.Contains(low, "threat"):
		return "Threat detected"
	default:
		return "SOSECURE Threat inSight"
	}
}

func (n *notifyBell) startBounce() {
	n.mu.Lock()
	if n.bounce > 0 {
		n.mu.Unlock()
		return
	}
	n.bounce = 6
	n.mu.Unlock()
	go func() {
		for {
			n.mu.Lock()
			left := n.bounce
			n.mu.Unlock()
			if left <= 0 {
				n.offsetY = 0
				fyne.Do(func() { n.Refresh() })
				return
			}
			n.offsetY = -3
			fyne.Do(func() { n.Refresh() })
			time.Sleep(80 * time.Millisecond)
			n.offsetY = 0
			fyne.Do(func() { n.Refresh() })
			time.Sleep(80 * time.Millisecond)
			n.mu.Lock()
			n.bounce--
			n.mu.Unlock()
		}
	}()
}

func (r *Router) buildNotifyBell() (*notifyBell, func()) {
	bell := newNotifyBell(r)
	refresh := func() {
		ev, err := r.client.History(r.ctx, 80)
		if err != nil {
			return
		}
		bell.ingest(ev)
	}
	return bell, refresh
}
