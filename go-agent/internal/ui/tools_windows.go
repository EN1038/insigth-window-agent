//go:build windows

package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/color"
	"io"
	"path/filepath"
	"strings"
	"time"

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
			if e.Kind == "scan.threat" && e.Meta != nil {
				path, _ := e.Meta["path"].(string)
				rule, _ := e.Meta["rule"].(string)
				engine, _ := e.Meta["engine"].(string)
				if path == "" {
					path = e.Message
				}
				parts := []string{}
				if rule != "" {
					parts = append(parts, rule)
				}
				if engine != "" {
					parts = append(parts, engine)
				}
				if path != "" {
					parts = append(parts, path)
				}
				if len(parts) > 0 {
					msg.Text = strings.Join(parts, "  ·  ")
				}
			}
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
	case strings.Contains(kind, "live"):
		return colorAccentCyan
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

	sync := widget.NewButtonWithIcon("Sync rules from server", theme.DownloadIcon(), nil)
	sync.OnTapped = func() {
		sync.Disable()
		sync.SetText("Syncing rules...")
		r.runThreatIntelSyncUI(func(err error, msg string) {
			sync.Enable()
			sync.SetText("Sync rules from server")
			if err != nil {
				dialog.ShowError(err, r.window)
				return
			}
			r.showYaraRules()
			if strings.TrimSpace(msg) == "" {
				msg = "Threat intelligence sync finished."
			}
			dialog.ShowInformation("YARA rules", humanizeNotifyMessage(msg), r.window)
		})
	}
	sync.Importance = widget.HighImportance

	stats := container.NewGridWithColumns(2,
		card(container.NewVBox(heading("RULE VERSION", 10, colorMuted), verVal)),
		card(container.NewVBox(heading("RULE FILES LOADED", 10, colorMuted), countVal)),
	)
	gap := muted("")
	if info.BehindServer {
		gap = muted(fmt.Sprintf("Behind Center by file count: local %d / server %d (names catalog is separate)", info.LocalCount, info.ServerCount))
	} else {
		gap = muted(fmt.Sprintf("In sync with Center file count (local %d / server %d)", info.LocalCount, info.ServerCount))
	}

	note := muted("Rule content is stored encrypted on disk and is never exposed in plaintext.\n" +
		"Rules are decrypted to a protected temp folder only during a scan, then wiped.")

	content := container.NewVBox(
		container.NewHBox(img(resIconYara, 40, 40), hspace(8), heading("YARA Rules", 18, colorText)),
		vspace(10),
		stats,
		vspace(6),
		updated,
		vspace(4),
		gap,
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
// Ssdeep DB
// ---------------------------------------------------------------------------

func (r *Router) showSsdeepTool() {
	st, _ := r.client.GetSettings(r.ctx)
	info, _ := r.client.SsdeepInfo(r.ctx)

	enabledVal := heading("Off", 22, colorMuted)
	if info.Enabled || st.SsdeepEnabled {
		enabledVal = heading("On", 22, colorSuccess)
	}
	ver := orDash(info.Version)
	if ver == "—" {
		ver = orDash(st.SsdeepDBVersion)
	}
	verVal := heading(ver, 16, colorAccentCyan)
	thresh := orDash(info.Threshold)
	if thresh == "—" || strings.TrimSpace(thresh) == "" {
		thresh = orDash(st.SsdeepThreshold)
	}
	if thresh == "—" || strings.TrimSpace(thresh) == "" {
		thresh = "80"
	}
	threshVal := heading(thresh, 22, colorText)
	loadedTxt := "—"
	if info.Total > 0 {
		loadedTxt = fmt.Sprintf("%d", info.Total)
	} else if info.Shards > 0 {
		loadedTxt = fmt.Sprintf("%d shards", info.Shards)
	}
	loadedVal := heading(loadedTxt, 22, colorPrimary)
	syncAt := muted("Last TI sync: " + orDash(st.LastTISyncRun))
	if info.UpdatedAt != "" {
		syncAt = muted("Index updated: " + info.UpdatedAt + "  ·  Last TI sync: " + orDash(st.LastTISyncRun))
	}

	sync := widget.NewButtonWithIcon("Sync ssdeep from server", theme.DownloadIcon(), nil)
	sync.OnTapped = func() {
		sync.Disable()
		sync.SetText("Syncing ssdeep...")
		r.runThreatIntelSyncUI(func(err error, msg string) {
			sync.Enable()
			sync.SetText("Sync ssdeep from server")
			if err != nil {
				dialog.ShowError(err, r.window)
				return
			}
			r.showSsdeepTool()
			if strings.TrimSpace(msg) == "" {
				msg = "Threat intelligence sync finished."
			}
			dialog.ShowInformation("Ssdeep", humanizeNotifyMessage(msg), r.window)
		})
	}
	sync.Importance = widget.HighImportance

	stats := container.NewGridWithColumns(4,
		card(container.NewVBox(heading("ENGINE", 10, colorMuted), enabledVal)),
		card(container.NewVBox(heading("DB VERSION", 10, colorMuted), verVal)),
		card(container.NewVBox(heading("HASHES", 10, colorMuted), loadedVal)),
		card(container.NewVBox(heading("THRESHOLD", 10, colorMuted), threshVal)),
	)

	note := muted("Ssdeep is a fuzzy-hash secondary scanner used alongside YARA.\n" +
		"Packs are downloaded from Center and matched during scans when the engine is enabled.")

	content := container.NewVBox(
		container.NewHBox(img(resIconBatch, 40, 40), hspace(8), heading("Ssdeep", 18, colorText)),
		vspace(10),
		stats,
		vspace(6),
		syncAt,
		vspace(12),
		sync,
		vspace(12),
		note,
	)
	d := dialog.NewCustom("Ssdeep", "Close", container.NewPadded(content), r.window)
	d.Resize(fyne.NewSize(620, 420))
	d.Show()
}

// ---------------------------------------------------------------------------
// Reports page (scan history) + Quarantine
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Detection Dashboard (sidebar Reports)
// ---------------------------------------------------------------------------

func (r *Router) showReports(setPage func(fyne.CanvasObject)) {
	r.stopTicker()

	kpiLastFiles := heading("—", 26, colorPrimary)
	kpiLastNew := heading("—", 26, colorAccentCyan)
	kpiLastMalware := heading("—", 26, colorError)
	kpiQuarantine := heading("—", 22, colorWarning)
	kpiRules := heading("—", 16, colorText)
	kpiSsdeep := heading("—", 14, colorAccentCyan)

	kpiCard := func(title string, val fyne.CanvasObject) fyne.CanvasObject {
		return card(container.NewPadded(container.NewVBox(
			heading(title, 10, colorMuted),
			vspace(4),
			val,
		)))
	}
	lastScanHint := muted("Last completed scan summary")
	kpis := container.NewVBox(
		lastScanHint,
		vspace(6),
		container.NewGridWithColumns(3,
			kpiCard("FILES (TOTAL)", kpiLastFiles),
			kpiCard("NEWLY SCANNED", kpiLastNew),
			kpiCard("MALWARE", kpiLastMalware),
		),
		vspace(8),
		container.NewGridWithColumns(3,
			kpiCard("QUARANTINED", kpiQuarantine),
			kpiCard("YARA RULES", kpiRules),
			kpiCard("SSDEEP DB", kpiSsdeep),
		),
	)

	protRT := heading("—", 13, colorMuted)
	protUSB := heading("—", 13, colorMuted)
	protSsdeep := heading("—", 13, colorMuted)
	protQuar := heading("—", 13, colorMuted)
	protPill := func(label string, val *canvas.Text) fyne.CanvasObject {
		return card(container.NewPadded(container.NewVBox(
			heading(label, 9, colorMuted),
			val,
		)))
	}
	protection := container.NewGridWithColumns(4,
		protPill("REAL-TIME", protRT),
		protPill("USB", protUSB),
		protPill("SSDEEP", protSsdeep),
		protPill("QUARANTINE", protQuar),
	)

	type dashRow struct {
		Time, Title, Detail string
		Accent              color.Color
	}
	detRows := []dashRow{}

	mkList := func(getRows func() []dashRow) *widget.List {
		return widget.NewList(
			func() int {
				n := len(getRows())
				if n == 0 {
					return 1
				}
				return n
			},
			func() fyne.CanvasObject {
				ts := canvasMuted("", colorMuted)
				title := heading("", 12, colorText)
				detail := muted("")
				return container.NewVBox(container.NewHBox(ts, hspace(8), title), detail)
			},
			func(i widget.ListItemID, o fyne.CanvasObject) {
				box := o.(*fyne.Container)
				top := box.Objects[0].(*fyne.Container)
				ts := top.Objects[0].(*canvas.Text)
				title := top.Objects[2].(*canvas.Text)
				detail := box.Objects[1].(*canvas.Text)
				rows := getRows()
				if len(rows) == 0 {
					ts.Text = ""
					title.Text = "No malware yet"
					title.Color = colorMuted
					detail.Text = ""
					ts.Refresh()
					title.Refresh()
					detail.Refresh()
					return
				}
				if i < 0 || i >= len(rows) {
					return
				}
				row := rows[i]
				ts.Text = row.Time
				title.Text = row.Title
				title.Color = row.Accent
				detail.Text = row.Detail
				ts.Refresh()
				title.Refresh()
				detail.Refresh()
			},
		)
	}

	detList := mkList(func() []dashRow { return detRows })
	detCard := card(container.NewBorder(
		container.NewPadded(sectionHeaderImg(resIconScan, "Recent malware")),
		nil, nil, nil,
		container.NewPadded(container.New(&fixedHeight{h: 160}, detList)),
	))

	scanHistBox := container.NewVBox(muted("No completed scans yet."))
	scanHistCard := card(container.NewBorder(
		container.NewPadded(sectionHeaderImg(resIconStat, "Scan history — expand a run for paths")),
		nil, nil, nil,
		container.NewPadded(container.New(&fixedHeight{h: 340}, container.NewVScroll(scanHistBox))),
	))

	quarantineBtn := widget.NewButtonWithIcon("Quarantine", theme.WarningIcon(), func() { r.showQuarantine() })
	logsBtn := widget.NewButtonWithIcon("Full log", theme.ListIcon(), func() { r.showViewLogs() })

	header := container.NewBorder(nil, nil,
		sectionHeaderImg(resIconStat, "Detection Dashboard"),
		container.NewHBox(logsBtn, quarantineBtn),
		layout.NewSpacer(),
	)

	body := container.NewVBox(
		header,
		vspace(10),
		kpis,
		vspace(10),
		sectionHeaderImg(resIconRT, "Protection status"),
		vspace(6),
		protection,
		vspace(12),
		scanHistCard,
		vspace(12),
		detCard,
		vspace(8),
	)
	setPage(container.NewPadded(container.NewVScroll(container.New(&flexWidth{}, body))))

	formatOnOff := func(on bool, label *canvas.Text) {
		if on {
			label.Text = "On"
			label.Color = colorSuccess
		} else {
			label.Text = "Off"
			label.Color = colorMuted
		}
		label.Refresh()
	}
	shortTime := func(t string) string {
		t = strings.TrimSpace(t)
		if t == "" {
			return "—"
		}
		if len(t) >= 19 {
			if t[10] == 'T' {
				return strings.Replace(t[5:16], "T", " ", 1)
			}
			return t[5:16]
		}
		if len(t) >= 10 {
			return t[:10]
		}
		return t
	}
	clip := func(s string, n int) string {
		s = strings.TrimSpace(s)
		if n > 0 && len(s) > n {
			return s[:n-1] + "…"
		}
		return s
	}

	metaStr := func(m map[string]any, key string) string {
		if m == nil {
			return ""
		}
		v, ok := m[key]
		if !ok || v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return t
		default:
			return fmt.Sprint(t)
		}
	}
	metaInt := func(m map[string]any, key string) int {
		s := strings.TrimSpace(metaStr(m, key))
		if s == "" {
			return 0
		}
		var n int
		fmt.Sscanf(s, "%d", &n)
		return n
	}

	buildScanHistory := func(hist []ipc.HistoryEvent) (fyne.CanvasObject, int, int, int) {
		type sessFile struct {
			path, result, rule, engine, score string
		}
		type sess struct {
			time, mode, status, runID string
			scanned, skipped, threats int
			items                     []sessFile
			fileTotal                 int
		}

		sessions := make([]sess, 0, 20)
		for _, e := range hist {
			if e.Kind != "scan.end" {
				continue
			}
			if len(sessions) >= 20 {
				break
			}
			rid := metaStr(e.Meta, "run_id")
			mode := metaStr(e.Meta, "mode")
			if mode == "" {
				mode = metaStr(e.Meta, "source")
			}
			st := metaStr(e.Meta, "status")
			if st == "" {
				st = "completed"
			}
			items := []sessFile{}
			fileTotal := 0
			if rid != "" {
				if resp, err := r.client.ScanRunFiles(r.ctx, rid, 0, 300); err == nil {
					fileTotal = resp.Total
					for _, row := range resp.Rows {
						score := ""
						if row.Score != 0 {
							score = fmt.Sprintf("%.0f", row.Score)
						}
						items = append(items, sessFile{
							path:   row.Path,
							result: row.Result,
							rule:   row.Rule,
							engine: row.Engine,
							score:  score,
						})
					}
				}
			}
			if len(items) == 0 {
				for _, te := range hist {
					if te.Kind != "scan.threat" {
						continue
					}
					if rid != "" && metaStr(te.Meta, "run_id") != rid {
						continue
					}
					path := metaStr(te.Meta, "path")
					if path == "" {
						path = te.Message
					}
					items = append(items, sessFile{
						path:   path,
						result: "infected",
						rule:   metaStr(te.Meta, "rule"),
						engine: metaStr(te.Meta, "engine"),
						score:  metaStr(te.Meta, "score"),
					})
				}
				fileTotal = len(items)
			}
			sessions = append(sessions, sess{
				time:      shortTime(e.Time),
				mode:      mode,
				status:    st,
				runID:     rid,
				scanned:   metaInt(e.Meta, "scanned"),
				skipped:   metaInt(e.Meta, "skipped"),
				threats:   metaInt(e.Meta, "threats"),
				items:     items,
				fileTotal: fileTotal,
			})
		}
		if len(sessions) == 0 {
			return muted("No completed scans yet. Run a scan to see file totals and path history."), 0, 0, 0
		}

		last := sessions[0]
		lastTotal := last.scanned + last.skipped
		if lastTotal == 0 {
			lastTotal = last.fileTotal
		}
		lastNew := last.scanned
		if lastNew == 0 && last.fileTotal > 0 {
			lastNew = last.fileTotal
		}
		lastMalware := last.threats

		acc := widget.NewAccordion()
		for _, s := range sessions {
			totalFiles := s.scanned + s.skipped
			title := fmt.Sprintf("%s  ·  %s  ·  total %d  (new %d · skipped %d)  ·  malware %d",
				s.time, orDash(s.mode), totalFiles, s.scanned, s.skipped, s.threats)
			if s.status != "" && s.status != "finished" && s.status != "completed" {
				title = fmt.Sprintf("%s  [%s]", title, s.status)
			}
			var detail fyne.CanvasObject
			if len(s.items) == 0 {
				detail = container.NewVBox(
					muted("No newly scanned paths in this run."),
					muted("Unchanged files were skipped and are not listed."),
				)
			} else {
				rows := make([]fyne.CanvasObject, 0, len(s.items)+2)
				rows = append(rows, muted(fmt.Sprintf(
					"Newly scanned paths in this run (%d shown). Malware shows rule + engine.",
					len(s.items))))
				rows = append(rows, vspace(6))
				for _, it := range s.items {
					infected := strings.EqualFold(it.result, "infected")
					accent := colorSuccess
					resultTag := "CLEAN"
					if infected {
						accent = colorError
						resultTag = "MALWARE"
					}
					engine := strings.TrimSpace(it.engine)
					if engine == "" {
						engine = "—"
					} else {
						engine = strings.ToUpper(engine)
					}
					rule := strings.TrimSpace(it.rule)
					if rule == "" {
						if infected {
							rule = "(unknown rule)"
						} else {
							rule = "—"
						}
					}
					titleLine := fmt.Sprintf("[%s]  %s", resultTag, clip(filepath.Base(it.path), 42))
					detailLine := fmt.Sprintf("engine %s  ·  rule %s", engine, rule)
					if it.score != "" && it.score != "0" {
						detailLine += "  ·  score " + it.score
					}
					detailLine += "  ·  " + it.path
					rows = append(rows, container.NewVBox(
						heading(titleLine, 12, accent),
						muted(clip(detailLine, 110)),
						vspace(6),
					))
				}
				if s.fileTotal > len(s.items) {
					rows = append(rows, muted(fmt.Sprintf("Showing %d of %d newly scanned files", len(s.items), s.fileTotal)))
				}
				detail = container.NewVBox(rows...)
			}
			acc.Append(widget.NewAccordionItem(title, container.NewPadded(detail)))
		}
		return acc, lastTotal, lastNew, lastMalware
	}

	stop := make(chan struct{})
	r.stopRefresh = stop
	refresh := func() {
		qItems, _ := r.client.Quarantine(r.ctx)
		rules, _ := r.client.RulesInfo(r.ctx)
		st, _ := r.client.GetSettings(r.ctx)
		hist, _ := r.client.History(r.ctx, 250)

		newDet := make([]dashRow, 0, 12)
		for _, it := range qItems {
			if len(newDet) >= 12 {
				break
			}
			newDet = append(newDet, dashRow{
				Time:   shortTime(it.IsolatedAt),
				Title:  clip(it.FileName, 40),
				Detail: clip("quarantine  ·  "+it.ThreatType+"  ·  "+it.OriginalPath, 72),
				Accent: colorError,
			})
		}
		for _, e := range hist {
			if len(newDet) >= 12 {
				break
			}
			if e.Kind != "scan.threat" {
				continue
			}
			path := metaStr(e.Meta, "path")
			if path == "" {
				path = e.Message
			}
			rule := metaStr(e.Meta, "rule")
			engine := metaStr(e.Meta, "engine")
			if engine == "" {
				engine = "yara"
			}
			detail := fmt.Sprintf("engine %s", strings.ToUpper(engine))
			if rule != "" {
				detail += "  ·  rule " + rule
			}
			detail += "  ·  " + path
			newDet = append(newDet, dashRow{
				Time:   shortTime(e.Time),
				Title:  clip(filepath.Base(path), 40),
				Detail: clip(detail, 90),
				Accent: colorError,
			})
		}

		ssdeepLabel := "Off"
		ssdeepColor := colorMuted
		if st.SsdeepEnabled {
			ssdeepLabel = "On"
			ssdeepColor = colorSuccess
			if v := strings.TrimSpace(st.SsdeepDBVersion); v != "" {
				ssdeepLabel = clip(v, 22)
				ssdeepColor = colorAccentCyan
			}
		}

		histUI, lastTotal, lastNew, lastMalware := buildScanHistory(hist)

		fyne.Do(func() {
			kpiLastFiles.Text = fmtCount(lastTotal)
			kpiLastNew.Text = fmtCount(lastNew)
			kpiLastMalware.Text = fmtCount(lastMalware)
			kpiQuarantine.Text = fmtCount(len(qItems))
			kpiRules.Text = fmtCount(rules.Count)
			kpiSsdeep.Text = ssdeepLabel
			kpiSsdeep.Color = ssdeepColor
			kpiLastFiles.Refresh()
			kpiLastNew.Refresh()
			kpiLastMalware.Refresh()
			kpiQuarantine.Refresh()
			kpiRules.Refresh()
			kpiSsdeep.Refresh()

			formatOnOff(st.RealtimeShield, protRT)
			formatOnOff(st.USBProtection, protUSB)
			formatOnOff(st.SsdeepEnabled, protSsdeep)
			formatOnOff(st.QuarantineOnDetect, protQuar)

			detRows = newDet
			detList.Refresh()

			scanHistBox.Objects = []fyne.CanvasObject{histUI}
			scanHistBox.Refresh()
		})
	}

	go func() {
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		refresh()
		for {
			select {
			case <-stop:
				return
			case <-r.ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
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
