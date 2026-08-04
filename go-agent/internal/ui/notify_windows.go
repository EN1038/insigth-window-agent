//go:build windows

package ui

import (
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
)

type notifyItem struct {
	Time    string
	Message string
}

type notifyBell struct {
	widget.BaseWidget
	router   *Router
	icon     *canvas.Image
	badge    *canvas.Text
	badgeBg  *canvas.Rectangle
	offsetY  float32
	unread   int
	bounce   int
	popup    *widget.PopUp
	mu       sync.Mutex
	seenKeys map[string]bool
	items    []notifyItem
}

func newNotifyBell(r *Router) *notifyBell {
	n := &notifyBell{
		router:   r,
		icon:     canvas.NewImageFromResource(theme.MailComposeIcon()),
		badge:    canvas.NewText("", colorOnAccent),
		badgeBg:  canvas.NewRectangle(colorError),
		seenKeys: map[string]bool{},
		items:    nil,
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
	txt := strconvItoa(u)
	if u > 9 {
		txt = "9+"
	}
	n.badge.Text = txt
	n.badge.Show()
	n.badgeBg.Show()
}

func strconvItoa(n int) string {
	if n <= 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 10 {
		return digits[n : n+1]
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func (n *notifyBell) Tapped(*fyne.PointEvent) {
	n.showDropdown()
}

func (n *notifyBell) Cursor() desktop.Cursor {
	return desktop.PointerCursor
}

func (n *notifyBell) showDropdown() {
	n.mu.Lock()
	items := append([]notifyItem(nil), n.items...)
	n.unread = 0
	n.mu.Unlock()
	n.refreshBadge()
	n.Refresh()

	rows := make([]fyne.CanvasObject, 0, len(items)+1)
	title := canvas.NewText("Notifications", colorText)
	title.TextStyle = fyne.TextStyle{Bold: true}
	rows = append(rows, title)
	if len(items) == 0 {
		rows = append(rows, canvasMuted("No recent updates", colorMuted))
	} else {
		for _, it := range items {
			t := it.Time
			if len(t) > 19 {
				t = t[:19]
			}
			t = strings.ReplaceAll(t, "T", " ")
			msg := canvas.NewText(clipNotify(it.Message, 56), colorText)
			msg.TextSize = 12
			rows = append(rows, container.NewVBox(
				canvasMuted(t, colorMuted),
				msg,
				divider(),
			))
		}
	}
	box := container.NewVBox(rows...)
	scroll := container.NewVScroll(box)
	const popupW, popupH float32 = 300, 240
	scroll.SetMinSize(fyne.NewSize(popupW-16, popupH-16))
	padded := container.NewPadded(scroll)

	if n.popup != nil {
		n.popup.Hide()
	}
	n.popup = widget.NewPopUp(padded, n.router.window.Canvas())
	n.popup.Resize(fyne.NewSize(popupW, popupH))

	// Position() is parent-relative; use absolute canvas coords so the menu
	// appears under the bell (top-right) instead of drifting to the left edge.
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

func clipNotify(s string, max int) string {
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func (n *notifyBell) ingest(events []ipc.HistoryEvent) {
	added := 0
	n.mu.Lock()
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind != "ui.notify" {
			continue
		}
		key := e.Time + "|" + e.Message
		if n.seenKeys[key] {
			continue
		}
		n.seenKeys[key] = true
		n.items = append([]notifyItem{{Time: e.Time, Message: e.Message}}, n.items...)
		if len(n.items) > 20 {
			n.items = n.items[:20]
		}
		n.unread++
		added++
	}
	unread := n.unread
	n.mu.Unlock()
	if added > 0 {
		n.startBounce()
	}
	_ = unread
	fyne.Do(func() {
		n.refreshBadge()
		n.Refresh()
	})
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
