//go:build windows

package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"image/color"
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/ipc"
)

// ---------------------------------------------------------------------------
// View Logs  ->  matches ViewLogsWindow.xaml
// ---------------------------------------------------------------------------

func (r *Router) showViewLogs() {
	events, err := r.client.History(r.ctx, 200)
	if err != nil {
		dialog.ShowError(err, r.window)
		return
	}

	list := widget.NewList(
		func() int { return len(events) },
		func() fyne.CanvasObject {
			ts := canvasMuted("", colorMuted)
			kind := heading("", 11, colorPrimary)
			msg := label("")
			return container.NewBorder(nil, nil, container.NewHBox(ts, hspace(6), kind), nil, msg)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			left := row.Objects[1].(*fyne.Container)
			ts := left.Objects[0].(*canvas.Text)
			kind := left.Objects[2].(*canvas.Text)
			msg := row.Objects[0].(*canvas.Text)
			e := events[i]
			t := e.Time
			if len(t) >= 19 {
				t = t[11:19]
			}
			ts.Text = t
			kind.Text = e.Kind
			kind.Color = kindColor(e.Kind)
			msg.Text = e.Message
			ts.Refresh()
			kind.Refresh()
			msg.Refresh()
		},
	)

	refresh := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
		if ev, e := r.client.History(r.ctx, 200); e == nil {
			events = ev
			list.Refresh()
		}
	})

	content := container.NewBorder(
		container.NewBorder(nil, nil, sectionHeaderImg(resIconLog, "Activity log"), refresh, layout.NewSpacer()),
		nil, nil, nil, list)
	d := dialog.NewCustom("View Logs", "Close", content, r.window)
	d.Resize(fyne.NewSize(760, 520))
	d.Show()
}

func kindColor(kind string) color.Color {
	switch {
	case strings.Contains(kind, "error"):
		return colorError
	case strings.Contains(kind, "warn"):
		return colorWarning
	case strings.Contains(kind, "threat"), strings.Contains(kind, "detect"):
		return colorError
	case strings.Contains(kind, "ok"), strings.Contains(kind, "approve"):
		return colorSuccess
	default:
		return colorPrimary
	}
}

// ---------------------------------------------------------------------------
// Yara rules
// ---------------------------------------------------------------------------

func (r *Router) showYaraRules() {
	info, _ := r.client.RulesInfo(r.ctx)

	verVal := heading(orDash(info.Version), 22, colorText)
	countVal := heading(fmtCount(info.Count), 22, colorPrimary)
	updated := muted("Last updated: " + orDash(info.UpdatedAt))

	sync := widget.NewButtonWithIcon("Sync rules from server", theme.DownloadIcon(), func() {
		if err := r.client.SyncRules(r.ctx); err != nil {
			dialog.ShowError(err, r.window)
			return
		}
		dialog.ShowInformation("YARA rules", "Rule sync requested. The list will update after download completes.", r.window)
	})
	sync.Importance = widget.HighImportance

	stats := container.NewGridWithColumns(2,
		card(container.NewVBox(heading("RULE VERSION", 10, colorMuted), verVal)),
		card(container.NewVBox(heading("RULES LOADED", 10, colorMuted), countVal)),
	)

	note := muted("Rule content is stored encrypted on disk and is never exposed in plaintext.\n" +
		"Rules are decrypted to a protected temp folder only during a scan, then wiped.")

	content := container.NewVBox(
		container.NewHBox(img(resIconYara, 40, 40), hspace(8), heading("YARA Rules", 18, colorText)),
		vspace(10),
		stats,
		vspace(6),
		updated,
		vspace(12),
		sync,
		vspace(12),
		note,
	)
	d := dialog.NewCustom("YARA Rules", "Close", container.NewPadded(content), r.window)
	d.Resize(fyne.NewSize(520, 420))
	d.Show()
}

// ---------------------------------------------------------------------------
// Hash tool
// ---------------------------------------------------------------------------

func (r *Router) showHashTool() {
	fileLbl := label("No file selected")
	hashEntry := widget.NewEntry()
	hashEntry.SetPlaceHolder("SHA-256 will appear here")
	hashEntry.Disable()

	copyBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if hashEntry.Text != "" {
			r.window.Clipboard().SetContent(hashEntry.Text)
		}
	})

	pick := widget.NewButtonWithIcon("Choose file…", theme.FolderOpenIcon(), func() {
		dialog.ShowFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil || rc == nil {
				return
			}
			defer rc.Close()
			fileLbl.Text = rc.URI().Name()
			fileLbl.Refresh()
			h := sha256.New()
			if _, err := io.Copy(h, rc); err != nil {
				dialog.ShowError(err, r.window)
				return
			}
			hashEntry.SetText(hex.EncodeToString(h.Sum(nil)))
		}, r.window)
	})
	pick.Importance = widget.HighImportance

	content := container.NewVBox(
		container.NewHBox(img(resIconHash, 40, 40), hspace(8), heading("File Hash (SHA-256)", 18, colorText)),
		vspace(10),
		pick,
		vspace(6),
		fileLbl,
		vspace(10),
		container.NewBorder(nil, nil, nil, copyBtn, hashEntry),
		vspace(8),
		muted("Compute a file's SHA-256 fingerprint to compare against threat intelligence."),
	)
	d := dialog.NewCustom("Hash", "Close", container.NewPadded(content), r.window)
	d.Resize(fyne.NewSize(560, 320))
	d.Show()
}

// ---------------------------------------------------------------------------
// Reports page (scan history) + Quarantine
// ---------------------------------------------------------------------------

func (r *Router) showReports(setPage func(fyne.CanvasObject)) {
	events, _ := r.client.History(r.ctx, 200)
	var scanEvents []ipc.HistoryEvent
	for _, e := range events {
		if strings.HasPrefix(e.Kind, "scan") || strings.Contains(e.Kind, "threat") ||
			strings.Contains(e.Kind, "detect") || strings.HasPrefix(e.Kind, "heartbeat") {
			scanEvents = append(scanEvents, e)
		}
	}

	list := widget.NewList(
		func() int { return len(scanEvents) },
		func() fyne.CanvasObject {
			ts := canvasMuted("", colorMuted)
			kind := heading("", 11, colorPrimary)
			msg := label("")
			return container.NewBorder(nil, nil, container.NewHBox(ts, hspace(6), kind), nil, msg)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			left := row.Objects[1].(*fyne.Container)
			ts := left.Objects[0].(*canvas.Text)
			kind := left.Objects[2].(*canvas.Text)
			msg := row.Objects[0].(*canvas.Text)
			e := scanEvents[i]
			t := e.Time
			if len(t) >= 19 {
				t = t[11:19]
			}
			ts.Text, kind.Text, kind.Color, msg.Text = t, e.Kind, kindColor(e.Kind), e.Message
			ts.Refresh()
			kind.Refresh()
			msg.Refresh()
		},
	)

	quarantineBtn := widget.NewButtonWithIcon("Quarantine", theme.WarningIcon(), func() { r.showQuarantine() })
	logsBtn := widget.NewButtonWithIcon("Full log", theme.ListIcon(), func() { r.showViewLogs() })

	header := container.NewBorder(nil, nil,
		sectionHeaderImg(resIconStat, "Reports & Activity"),
		container.NewHBox(logsBtn, quarantineBtn),
		layout.NewSpacer(),
	)
	setPage(container.NewPadded(container.NewBorder(header, nil, nil, nil, card(list))))
}

func (r *Router) showQuarantine() {
	items, err := r.client.Quarantine(r.ctx)
	if err != nil {
		dialog.ShowError(err, r.window)
		return
	}

	var content fyne.CanvasObject
	if len(items) == 0 {
		content = container.NewCenter(container.NewVBox(
			container.NewCenter(muted("No files in quarantine")),
			container.NewCenter(muted("Threats detected during scans will appear here.")),
		))
	} else {
		list := widget.NewList(
			func() int { return len(items) },
			func() fyne.CanvasObject {
				name := heading("", 12, colorText)
				meta := muted("")
				return container.NewVBox(name, meta)
			},
			func(i widget.ListItemID, o fyne.CanvasObject) {
				box := o.(*fyne.Container)
				name := box.Objects[0].(*canvas.Text)
				meta := box.Objects[1].(*canvas.Text)
				it := items[i]
				name.Text = it.FileName + "  —  " + it.ThreatType
				meta.Text = it.IsolatedAt + "   " + it.OriginalPath
				name.Refresh()
				meta.Refresh()
			},
		)
		content = list
	}

	d := dialog.NewCustom("Quarantine", "Close", container.NewPadded(content), r.window)
	d.Resize(fyne.NewSize(720, 480))
	d.Show()
}
