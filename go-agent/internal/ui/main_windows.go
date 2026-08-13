//go:build windows

package ui

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/ipc"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/sysinfo"
	"github.com/sosecure/insite-agent/internal/version"
)

// ---------------------------------------------------------------------------
// Main window: 65px icon sidebar + header stats + page host + footer
// ---------------------------------------------------------------------------

func (r *Router) showMain() {
	r.stopTicker()
	r.window.SetPadded(false)
	r.window.Resize(fyne.NewSize(1100, 650))
	r.window.SetFixedSize(true)
	r.window.CenterOnScreen()

	pageHost := container.NewStack()
	setPage := func(o fyne.CanvasObject) {
		r.stopTicker()
		pageHost.Objects = []fyne.CanvasObject{o}
		pageHost.Refresh()
	}

	topChrome := r.buildTopChrome()
	statsBar, refreshHeader := r.buildStatsBar()
	sidebar := r.buildSidebar(setPage)

	footerBg := canvas.NewRectangle(colorBg)
	footerBg.SetMinSize(fyne.NewSize(10, 22))
	footer := container.NewStack(footerBg, container.NewCenter(
		canvasMuted("© Copyright SOSECURE Threat inSight. All Rights Reserved", colorMuted)))

	// Sidebar spans full window height; everything else lives in the right column.
	rightBody := container.NewBorder(statsBar, footer, nil, nil, pageHost)
	rightPanel := container.NewBorder(topChrome, nil, nil, nil, rightBody)
	root := container.NewBorder(nil, nil, sidebar, nil, rightPanel)
	r.window.SetContent(root)

	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		refreshHeader()
		if r.notifyRefresh != nil {
			r.notifyRefresh()
		}
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-t.C:
				refreshHeader()
				if r.notifyRefresh != nil {
					r.notifyRefresh()
				}
			}
		}
	}()

	r.showOverview(setPage)
}

func (r *Router) buildSidebar(setPage func(fyne.CanvasObject)) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorSidebar)

	var buttons []*navButton
	mk := func(res fyne.Resource, onTap func(*navButton)) *navButton {
		nb := newNavButton(res)
		nb.onTap = func() {
			for _, b := range buttons {
				b.setActive(b == nb)
			}
			onTap(nb)
		}
		buttons = append(buttons, nb)
		return nb
	}

	overviewBtn := mk(resIconMain, func(*navButton) { r.showOverview(setPage) })
	reportsBtn := mk(resIconStat, func(*navButton) { r.showReports(setPage) })
	settingsBtn := mk(resIconSet, func(*navButton) { r.showSettings(setPage) })
	aboutBtn := mk(resIconInfo, func(*navButton) { r.showAbout(setPage) })
	overviewBtn.setActive(true)

	nav := container.NewVBox(
		vspace(10),
		overviewBtn, reportsBtn, settingsBtn, aboutBtn,
	)

	brand := container.NewVBox(
		container.NewCenter(img(resLogoMark, 40, 44)),
		container.NewCenter(heading("SOSECURE", 10, colorText)),
		vspace(12),
	)

	col := container.NewBorder(nav, brand, nil, nil, layout.NewSpacer())
	bg.SetMinSize(fyne.NewSize(sidebarW, 1))
	return container.NewStack(bg, container.New(&fixedWidth{w: sidebarW}, col))
}

func (r *Router) buildTopChrome() fyne.CanvasObject {
	bg := canvas.NewRectangle(color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xcc})
	// Hide (not Close): Close destroys the window; tray Open can no longer restore it.
	closeBtn := chromeCloseButton(func() {
		r.markWindowHidden(true)
		r.window.Hide()
	})
	bell, refreshBell := r.buildNotifyBell()
	r.notifyRefresh = refreshBell
	right := container.NewHBox(bell, hspace(6), closeBtn)
	drag := container.NewMax(newDragBar(func() uintptr { return r.windowHWND() }))
	return draggableTopBar(bg, 36, hspace(1), right, drag)
}

func (r *Router) buildStatsBar() (fyne.CanvasObject, func()) {
	bg := canvas.NewRectangle(colorBg)

	siteVal := heading("GENERAL SITE", 13, colorText)
	ipVal := heading("—", 13, colorText)
	osVal := heading("—", 11, colorText)
	statusDotV := statusDot(colorError, 10)
	statusVal := heading("OFFLINE", 13, colorText)
	statusTime := canvasMuted("", colorMuted)

	stat := func(cap string, val fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(heading(cap, 9, colorMuted), val)
	}
	statusCol := container.NewVBox(
		heading("STATUS", 9, colorMuted),
		container.NewHBox(container.NewCenter(statusDotV), hspace(4), statusVal, hspace(4), container.NewCenter(statusTime)),
	)

	stats := container.NewGridWithColumns(4,
		stat("SITE", siteVal),
		stat("IP", ipVal),
		stat("OS", osVal),
		statusCol,
	)

	bar := container.New(&fixedHeight{h: 68}, container.NewStack(bg, container.NewBorder(nil, nil,
		container.NewHBox(hspace(16), stats), nil, layout.NewSpacer())))

	refresh := func() {
		siteName := ""
		if cfg, err := r.client.GetConfig(r.ctx); err == nil && strings.TrimSpace(cfg.SiteName) != "" {
			siteName = strings.ToUpper(cfg.SiteName)
		}
		ip := sysinfo.LocalIPv4()
		osDesc := shorten(sysinfo.OsDescription(), 26)
		online, _ := r.client.TestConnection(r.ctx)
		now := time.Now().Format("2006.01.02 / 15.04.05")
		fyne.Do(func() {
			if siteName != "" {
				siteVal.Text = siteName
			}
			ipVal.Text = ip
			osVal.Text = osDesc
			if online {
				statusDotV.FillColor = colorStatusGrn
				statusVal.Text = "ONLINE"
			} else {
				statusDotV.FillColor = colorError
				statusVal.Text = "OFFLINE"
			}
			statusTime.Text = "(" + now + ")"
			siteVal.Refresh()
			ipVal.Refresh()
			osVal.Refresh()
			statusDotV.Refresh()
			statusVal.Refresh()
			statusTime.Refresh()
		})
	}
	return bar, refresh
}

// ---------------------------------------------------------------------------
// Overview page  ->  matches OverviewPage.xaml
// ---------------------------------------------------------------------------

func (r *Router) showOverview(setPage func(fyne.CanvasObject)) {
	// LEFT COLUMN — scan controls (legacy OverviewPage left stack)
	startScan := func(scanType, path string) {
		resp, err := r.client.StartScan(r.ctx, scanType, path)
		if err != nil {
			dialog.ShowError(err, r.window)
			return
		}
		if !resp.OK {
			msg := resp.Message
			if strings.TrimSpace(msg) == "" {
				msg = "Cannot start scan"
			}
			dialog.ShowInformation("Scan", msg, r.window)
		}
	}
	fullScan := newScanActionButton(resIconScan, "FULL SCAN", true, 80, func() {
		startScan("full", "")
	})
	customScan := newScanActionButton(resIconSet, "CUSTOM SCAN", false, 50, func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			startScan("custom", u.Path())
		}, r.window)
	})

	st, _ := r.client.GetSettings(r.ctx)
	typeGroup := widget.NewRadioGroup([]string{"REAL TIME", "ON-DEMAND"}, nil)
	typeGroup.Horizontal = false
	if st.RealtimeShield {
		typeGroup.SetSelected("REAL TIME")
	} else {
		typeGroup.SetSelected("ON-DEMAND")
	}
	typeGroup.OnChanged = func(sel string) {
		wantRT := sel == "REAL TIME"
		if err := r.client.UpdateSettings(r.ctx, ipc.UpdateSettingsRequest{
			RealtimeShield: boolPtr(wantRT),
		}); err != nil {
			// Revert UI on failure.
			if wantRT {
				typeGroup.SetSelected("ON-DEMAND")
			} else {
				typeGroup.SetSelected("REAL TIME")
			}
			dialog.ShowError(err, r.window)
			return
		}
	}

	stopCtrl := newStopScanControl(func() { _ = r.client.StopScan(r.ctx) })

	leftItems := []fyne.CanvasObject{
		fullScan,
		vspace(8),
		customScan,
		vspace(20),
		container.NewCenter(heading("TYPE SCAN", 10, colorMuted)),
		vspace(8),
		container.NewCenter(container.New(&fixedWidth{w: 200}, typeGroup)),
		vspace(14),
		container.NewCenter(stopCtrl),
	}
	if r.embedded {
		warn := widget.NewLabel("Standalone UI — realtime / schedule / login scan run only while this window stays open. Start the Windows service for always-on protection.")
		warn.Wrapping = fyne.TextWrapWord
		warn.Importance = widget.WarningImportance
		leftItems = append([]fyne.CanvasObject{warn, vspace(8)}, leftItems...)
	}
	leftCol := container.NewVBox(leftItems...)
	leftScroll := container.NewVScroll(leftCol)
	// fillParent: do not report a fixed MinHeight — overviewH=520 used to exceed
	// the remaining window (650 − chrome − stats − footer) and Fyne grew the
	// splash window, leaving a thin top edge above the black title bar.
	leftPanel := card(container.New(&fillParent{}, leftScroll))

	// RIGHT COLUMN — metrics + ring + live log inside one card
	fileCount := heading("0", 24, colorSuccess)
	detectCount := heading("0", 40, colorError)
	metrics := container.NewVBox(
		heading("NUMBER OF FILE", 10, colorMuted),
		fileCount,
		vspace(12),
		heading("DETECT FILE", 10, colorMuted),
		detectCount,
		layout.NewSpacer(),
	)

	ring := newProgressRing()
	pct := heading("0", 56, colorText)
	pctUnit := canvasMuted("%", colorMuted)
	pctBox := container.NewStack(
		container.New(&fixedSize{w: 200, h: 200}, ring.canvas),
		container.NewCenter(container.NewVBox(
			container.NewCenter(pct),
			container.NewCenter(pctUnit),
		)),
	)
	scanPhase := canvasMuted("Ready", colorMuted)
	scanPhase.TextSize = 11
	scanPhase.Alignment = fyne.TextAlignCenter
	scanEngine := canvasMuted("", colorAccentCyan)
	scanEngine.TextSize = 10
	scanEngine.Alignment = fyne.TextAlignCenter
	scanFile := canvasMuted("", colorMuted)
	scanFile.TextSize = 10
	scanFile.Alignment = fyne.TextAlignCenter
	ringCol := container.NewVBox(
		pctBox,
		vspace(4),
		container.NewCenter(scanPhase),
		container.NewCenter(scanEngine),
		container.NewCenter(scanFile),
	)

	logEvents := []ipc.HistoryEvent{}
	logList := widget.NewList(
		func() int { return len(logEvents) },
		func() fyne.CanvasObject {
			ts := canvas.NewText("", colorAccentCyan)
			ts.TextSize = 10
			msg := canvas.NewText("", colorText)
			msg.TextSize = 10
			return container.NewHBox(
				container.New(&fixedWidth{w: 44}, ts),
				canvasMuted(" | ", colorCardBorder),
				msg,
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			row := o.(*fyne.Container)
			ts := row.Objects[0].(*fyne.Container).Objects[0].(*canvas.Text)
			msg := row.Objects[2].(*canvas.Text)
			e := logEvents[i]
			t := e.Time
			if len(t) >= 19 {
				t = t[11:19]
			}
			ts.Text = t
			msg.Text = truncateMiddle(e.Message, 90)
			msg.Color = kindColor(e.Kind)
			ts.Refresh()
			msg.Refresh()
		},
	)
	logPanel := liveLogPanel(logList)

	// Pack metrics + ring on the left (tight gap so the ring sits beside the counts).
	metricsAndRing := container.NewHBox(
		container.New(&fixedWidth{w: 120}, metrics),
		hspace(4),
		container.New(&fixedWidth{w: 200}, ringCol),
	)
	rightCardBody := container.NewBorder(
		nil, nil, nil,
		container.New(&fixedWidth{w: 300}, logPanel),
		container.NewHBox(metricsAndRing, layout.NewSpacer()),
	)
	rightCard := card(container.NewPadded(rightCardBody))

	tools := container.NewGridWithColumns(5,
		toolCard(resIconLog, "VIEW LOGS", func() { r.showViewLogs() }),
		toolCard(resIconYara, "YARA RULES", func() { r.showYaraRules() }),
		toolCard(resIconHash, "HASH", func() { r.showHashTool() }),
		toolCardText("ssdeep", "SSDEEP", func() { r.showSsdeepTool() }),
		toolCard(theme.WarningIcon(), "QUARANTINE", func() { r.showQuarantine() }),
	)

	rightInner := container.NewBorder(nil,
		container.NewVBox(vspace(12), container.New(&fixedHeight{h: 132}, tools)),
		nil, nil, rightCard)

	page := container.NewBorder(nil, nil,
		container.New(&fixedWidth{w: 248}, leftPanel),
		nil,
		container.NewPadded(rightInner),
	)
	// Cap MinSize so Overview cannot stretch the fixed 1100×650 splash window.
	setPage(container.NewPadded(container.New(&flexWidth{}, container.New(&fillParent{}, page))))

	// Refresh loop
	stop := make(chan struct{})
	r.stopRefresh = stop
	refresh := func() {
		ss, err := r.client.ScanStatus(r.ctx)
		if err != nil {
			return
		}
		ev, evErr := r.client.History(r.ctx, 40)
		fyne.Do(func() {
			busy := ss.Scanning
			fullScan.setEnabled(!busy)
			customScan.setEnabled(!busy)
			typeGroup.Disable()
			if !busy {
				typeGroup.Enable()
			}
			stLower := strings.ToLower(strings.TrimSpace(ss.ScanType))
			fullScan.setActive(busy && stLower == "full")
			customScan.setActive(busy && (stLower == "custom" || stLower == "silent"))

			fileCount.Text = fmtCount(ss.Scanned)
			if busy && !ss.DiscoveryDone {
				fileCount.Text = fmtCount(ss.Total)
			}
			detectCount.Text = fmtCount(ss.Threats)

			frac := 0.0
			pctLabel := "0"
			phase := "Ready"
			engineHint := ""
			fileHint := ""
			modeLabel := overviewScanModeLabel(ss.ScanType, ss.Source)

			switch {
			case busy && (strings.EqualFold(ss.Status, "finalizing") || strings.Contains(strings.ToLower(ss.Message), "quarantin") || strings.Contains(strings.ToLower(ss.Message), "reporting")):
				frac = 1
				pctLabel = "100"
				phase = modeLabel
				if msg := strings.TrimSpace(ss.Message); msg != "" {
					phase = modeLabel + " · " + msg
				}
				fileHint = firstNonEmpty(ss.CurrentPath, ss.CurrentFile)
			case busy && !ss.DiscoveryDone:
				// Soft meter — do not claim overall % while Total is still growing.
				frac = 0.08 + 0.22*math.Mod(float64(ss.Total%500)/500.0, 1.0)
				pctLabel = "…"
				phase = modeLabel + " · Discovering"
				if ss.Message != "" {
					phase = modeLabel + " · " + ss.Message
				} else {
					phase = fmt.Sprintf("%s · Discovering… found %d · scanned %d", modeLabel, ss.Total, ss.Scanned)
				}
				engineHint = "DISCOVER"
				fileHint = firstNonEmpty(ss.CurrentPath, ss.CurrentFile)
			case busy:
				if ss.Total > 0 {
					frac = float64(ss.Scanned) / float64(ss.Total)
					if frac > 1 {
						frac = 1
					}
				} else {
					frac = 0.05
				}
				pctLabel = fmtCount(int(frac * 100))
				phase = modeLabel
				if ss.Message != "" {
					phase = modeLabel + " · " + ss.Message
				} else {
					phase = fmt.Sprintf("%s · Scanning… %d / %d", modeLabel, ss.Scanned, ss.Total)
				}
				engineHint = overviewEngineLabel(ss.CurrentEngine)
				fileHint = firstNonEmpty(ss.CurrentPath, ss.CurrentFile)
			default:
				if ss.Total > 0 && strings.TrimSpace(ss.Message) != "" {
					frac = float64(ss.Scanned) / float64(ss.Total)
					pctLabel = fmtCount(int(frac * 100))
					phase = ss.Message
				} else {
					phase = "Ready"
				}
			}

			ring.set(frac)
			pct.Text = pctLabel
			if pctLabel == "…" {
				pctUnit.Text = ""
			} else {
				pctUnit.Text = "%"
			}
			scanPhase.Text = truncateText(phase, 48)
			scanEngine.Text = engineHint
			scanFile.Text = truncateMiddle(fileHint, 48)
			fileCount.Refresh()
			detectCount.Refresh()
			pct.Refresh()
			pctUnit.Refresh()
			scanPhase.Refresh()
			scanEngine.Refresh()
			scanFile.Refresh()
			stopCtrl.setScanning(busy)
			if evErr == nil {
				logEvents = filterScanEvents(ev, 40)
				if live := liveScanLogEvent(ss); live != nil {
					logEvents = append([]ipc.HistoryEvent{*live}, logEvents...)
					if len(logEvents) > 40 {
						logEvents = logEvents[:40]
					}
				}
				logList.Refresh()
			}
		})
	}
	go func() {
		refresh()
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

func filterScanEvents(all []ipc.HistoryEvent, max int) []ipc.HistoryEvent {
	out := make([]ipc.HistoryEvent, 0, len(all))
	for _, e := range all {
		k := strings.ToLower(strings.TrimSpace(e.Kind))
		switch {
		case strings.HasPrefix(k, "scan."):
			out = append(out, e)
		case strings.Contains(k, "threat"), strings.Contains(k, "detect"):
			out = append(out, e)
		case strings.Contains(k, "yara"), strings.Contains(k, "hash"), strings.Contains(k, "quarantine"):
			out = append(out, e)
		}
	}

	// Show only the latest scan session: from the newest entries down to (and including)
	// the most recent scan.start marker. History is returned newest-first.
	cut := -1
	for i, e := range out {
		k := strings.ToLower(strings.TrimSpace(e.Kind))
		if k == "scan.start" || strings.Contains(k, "scan.start") {
			cut = i
			break
		}
		// Back-compat with older messages.
		if strings.Contains(strings.ToLower(e.Message), "scan started") {
			cut = i
			break
		}
	}
	if cut >= 0 {
		out = out[:cut+1]
	}

	if max > 0 && len(out) > max {
		out = out[:max]
	}
	// If nothing scan-related yet, show a friendly placeholder instead of heartbeats.
	if len(out) == 0 {
		return []ipc.HistoryEvent{{
			Time:    time.Now().Format(time.RFC3339),
			Kind:    "scan.wait",
			Message: "No scan events yet. Start a scan to see activity here.",
		}}
	}
	return out
}

// ---------------------------------------------------------------------------
// Settings page  ->  matches SettingsPage.xaml
// ---------------------------------------------------------------------------

func (r *Router) showSettings(setPage func(fyne.CanvasObject)) {
	st, err := r.client.GetSettings(r.ctx)
	if err != nil {
		setPage(container.NewCenter(label("Failed to load settings: " + err.Error())))
		return
	}

	rt := widget.NewCheck("", nil)
	rt.SetChecked(st.RealtimeShield)
	usb := widget.NewCheck("", nil)
	usb.SetChecked(st.USBProtection)
	auto := widget.NewCheck("", nil)
	auto.SetChecked(st.AutoScanOnLogin)

	batchIdx := settings.DailyTimeSelectIndex(st.BatchJobEveryDay)
	tiIdx := settings.IntervalSelectIndex(st.TISyncEveryDay, settings.DefaultTISyncIntervalMinutes)
	updIdx := settings.AgentUpdateSelectIndex(st.AgentUpdateSchedule)
	batchLabels := settings.DailyTimePresets()
	labels := settings.IntervalPresetLabels()
	updLabels := settings.AgentUpdatePresetLabels()

	batch := widget.NewSelect(batchLabels, nil)
	batch.SetSelectedIndex(batchIdx)
	tiSync := widget.NewSelect(labels, nil)
	tiSync.SetSelectedIndex(tiIdx)
	agentUpdSched := widget.NewSelect(updLabels, nil)
	agentUpdSched.SetSelectedIndex(updIdx)

	excl := widget.NewMultiLineEntry()
	excl.SetText(st.ExclusionPaths)
	excl.SetMinRowsVisible(3)

	scanExt := widget.NewMultiLineEntry()
	scanExt.SetText(st.ScanExtensions)
	scanExt.SetMinRowsVisible(3)

	threshold := widget.NewEntry()
	threshold.SetText(st.SsdeepThreshold)
	threshold.SetPlaceHolder("85")

	protection := card(container.NewVBox(
		sectionHeaderImg(resIconRT, "Protection"),
		vspace(4),
		toggleRowImg(resIconRT, "Real-time protection", "Scan files the moment they are accessed", rt),
		divider(),
		toggleRowImg(resIconUSB, "USB protection", "Automatically scan removable drives", usb),
		divider(),
		toggleRowImg(resIconConn, "Auto scan on login", "Run a login scan when a user signs in (not on agent start)", auto),
	))

	scheduleItems := []fyne.CanvasObject{
		sectionHeaderImg(resIconBatch, "Scheduled scan & sync"),
		vspace(4),
		fieldLabel("Batch scan time (once daily)"),
		batch,
		vspace(8),
		fieldLabel("Threat intelligence sync (rules + ssdeep)"),
		tiSync,
		vspace(8),
		fieldLabel("Agent update check"),
		agentUpdSched,
		vspace(8),
		fieldLabel("Excluded paths (one per line, empty by default)"),
		excl,
		vspace(8),
		fieldLabel("Scan extensions (comma-separated)"),
		scanExt,
	}
	schedule := card(container.NewVBox(scheduleItems...))

	ssdeepCard := card(container.NewVBox(
		sectionHeaderImg(resIconYara, "Ssdeep"),
		vspace(4),
		fieldLabel("Match threshold (0–100)"),
		threshold,
	))

	rulesVer := muted(fmt.Sprintf("local=%s  server=%s  ver=%s",
		orDash(st.LocalRulesCount), orDash(st.ServerRulesCount), orDash(st.RulesVersion)))
	ssdeepInfo, _ := r.client.SsdeepInfo(r.ctx)
	ssdeepHashes := "—"
	if ssdeepInfo.Total > 0 {
		ssdeepHashes = fmt.Sprintf("%d", ssdeepInfo.Total)
	}
	ssdeepVer := orDash(ssdeepInfo.Version)
	if ssdeepVer == "—" {
		ssdeepVer = orDash(st.SsdeepDBVersion)
	}
	ssdeepLine := muted(fmt.Sprintf("ssdeep hashes=%s  ver=%s", ssdeepHashes, ssdeepVer))
	syncBtn := widget.NewButtonWithIcon("Sync now", theme.DownloadIcon(), nil)
	syncBtn.OnTapped = func() {
		syncBtn.Disable()
		syncBtn.SetText("Syncing...")
		r.runThreatIntelSyncUI(func(err error, msg string) {
			syncBtn.Enable()
			syncBtn.SetText("Sync now")
			if err != nil {
				dialog.ShowError(err, r.window)
				return
			}
			// Reload settings page so Center values appear without leaving the page.
			r.showSettings(setPage)
			if strings.TrimSpace(msg) == "" {
				msg = "Threat intelligence sync finished."
			}
			dialog.ShowInformation("Threat intelligence", humanizeNotifyMessage(msg), r.window)
		})
	}
	rulesCard := card(container.NewVBox(
		sectionHeaderImg(resIconYara, "Threat intelligence"),
		vspace(4),
		container.NewBorder(nil, nil, container.NewVBox(label("Threat rules"), rulesVer, ssdeepLine), syncBtn),
	))

	curVer := orDash(st.AgentVersionCurrent)
	if curVer == "-" {
		curVer = version.AgentVersion
	}
	tgtVer := orDash(st.AgentVersionTarget)
	updStatus := orDash(st.AgentUpdateStatus)
	checkBtn := widget.NewButtonWithIcon("Check update", theme.ViewRefreshIcon(), nil)
	installBtn := widget.NewButtonWithIcon("Update now", theme.DownloadIcon(), nil)
	checkBtn.OnTapped = func() {
		checkBtn.Disable()
		installBtn.Disable()
		checkBtn.SetText("Checking...")
		go func() {
			out, err := r.client.CheckAgentUpdate(r.ctx)
			fyne.Do(func() {
				checkBtn.Enable()
				installBtn.Enable()
				checkBtn.SetText("Check update")
				if err != nil {
					dialog.ShowError(err, r.window)
					return
				}
				r.showSettings(setPage)
				dialog.ShowInformation("Agent update", out.Message, r.window)
			})
		}()
	}
	installBtn.OnTapped = func() {
		dialog.ShowConfirm("Install assigned version",
			"Download and install the Center-assigned agent version now?\nThe watchdog will restart the agent service.",
			func(ok bool) {
				if !ok {
					return
				}
				checkBtn.Disable()
				installBtn.Disable()
				installBtn.SetText("Downloading...")

				progressMsg := canvasMuted("Downloading agent update package from Center...", colorMuted)
				progressBar := widget.NewProgressBarInfinite()
				loadingContent := container.NewVBox(progressMsg, vspace(10), progressBar)
				loadingDlg := dialog.NewCustomWithoutButtons("Downloading Agent Update", container.NewPadded(loadingContent), r.window)
				loadingDlg.Resize(fyne.NewSize(440, 140))
				loadingDlg.Show()

				go func() {
					out, err := r.client.InstallAgentUpdate(r.ctx)
					fyne.Do(func() {
						loadingDlg.Hide()
						checkBtn.Enable()
						installBtn.Enable()
						installBtn.SetText("Update now")
						if err != nil {
							dialog.ShowError(err, r.window)
							return
						}
						r.showSettings(setPage)
						dialog.ShowInformation("Agent update", out.Message, r.window)
					})
				}()
			}, r.window)
	}
	installBtn.Importance = widget.HighImportance
	updateCard := card(container.NewVBox(
		sectionHeaderImg(resIconSet, "Agent update"),
		vspace(4),
		muted("Current: "+curVer+"  ·  Target: "+tgtVer),
		vspace(4),
		muted("Status: "+updStatus),
		vspace(8),
		container.NewGridWithColumns(2, checkBtn, installBtn),
	))

	save := widget.NewButtonWithIcon("Save settings", theme.DocumentSaveIcon(), func() {
		intervalAt := func(sel *widget.Select, def int) string {
			idx := sel.SelectedIndex()
			if idx < 0 || idx >= len(settings.IntervalPresets) {
				return strconv.Itoa(def)
			}
			return strconv.Itoa(settings.IntervalPresets[idx])
		}
		agentUpdateAt := func(sel *widget.Select) string {
			idx := sel.SelectedIndex()
			presets := settings.AgentUpdateIntervalPresets()
			if idx < 0 || idx >= len(presets) {
				return strconv.Itoa(settings.DefaultAgentUpdateIntervalMinutes)
			}
			return strconv.Itoa(presets[idx])
		}
		dailyAt := func(sel *widget.Select) string {
			idx := sel.SelectedIndex()
			presets := settings.DailyTimePresets()
			if idx < 0 || idx >= len(presets) {
				return settings.DefaultBatchDailyHHmm
			}
			return presets[idx]
		}
		if err := r.client.UpdateSettings(r.ctx, ipc.UpdateSettingsRequest{
			RealtimeShield:      boolPtr(rt.Checked),
			USBProtection:       boolPtr(usb.Checked),
			AutoScanOnLogin:     boolPtr(auto.Checked),
			BatchJobEveryDay:    dailyAt(batch),
			TISyncEveryDay:      intervalAt(tiSync, settings.DefaultTISyncIntervalMinutes),
			AgentUpdateSchedule: agentUpdateAt(agentUpdSched),
			ExclusionPaths:      strPtr(excl.Text),
			ScanExtensions:      scanExt.Text,
			QuickScanPaths:      nil,
			SsdeepEnabled:       boolPtr(settings.ForcedSsdeepEnabled),
			SsdeepThreshold:     threshold.Text,
			SsdeepReportAPI:     boolPtr(settings.ForcedSsdeepReportAPI),
			QuarantineOnDetect:  boolPtr(settings.ForcedQuarantineOnDetect),
			SendSsdeepCandidate: boolPtr(settings.ForcedSendSsdeepCandidate),
		}); err != nil {
			dialog.ShowError(err, r.window)
			return
		}
		dialog.ShowInformation("Saved", "Your settings have been updated.", r.window)
	})
	save.Importance = widget.HighImportance

	logout := newDangerButton("Sign out", func() {
		dialog.ShowConfirm("Sign out", "Sign out of this agent?", func(ok bool) {
			if !ok {
				return
			}
			_ = r.client.Logout(r.ctx)
			r.showLogin()
		}, r.window)
	})

	body := container.NewVBox(
		protection, vspace(6),
		ssdeepCard, vspace(6),
		schedule, vspace(6),
		rulesCard, vspace(6),
		updateCard, vspace(6),
		container.NewGridWithColumns(2, logout, save),
	)
	setPage(container.NewPadded(container.NewVScroll(container.New(&flexWidth{}, body))))
}

// ---------------------------------------------------------------------------
// About page  ->  matches AboutPage.xaml
// ---------------------------------------------------------------------------

func (r *Router) showAbout(setPage func(fyne.CanvasObject)) {
	// Re-lock size: long Info labels previously inflated MinSize and grew the window,
	// leaving an empty dark strip on the right.
	r.window.SetFixedSize(true)
	r.window.Resize(fyne.NewSize(1100, 650))

	onlineNow, _ := r.client.TestConnection(r.ctx)
	status, _ := r.client.Status(r.ctx)
	cfg, _ := r.client.GetConfig(r.ctx)
	rulesInfo, _ := r.client.RulesInfo(r.ctx)
	ssdeepInfo, _ := r.client.SsdeepInfo(r.ctx)
	st, _ := r.client.GetSettings(r.ctx)
	scan, _ := r.client.ScanStatus(r.ctx)

	onlineLbl := "OFFLINE"
	onlineColor := colorError
	// Same source as header: live TestConnection updates cache; Status.Online reads it.
	if onlineNow || status.Online {
		onlineLbl = "ONLINE"
		onlineColor = colorSuccess
	}
	scanningLbl := "IDLE"
	scanColor := colorMuted
	if scan.Scanning {
		scanningLbl = "SCANNING"
		scanColor = colorWarning
	}

	dataDir := truncateText(config.DataBaseDir(), 56)
	installDir := truncateText(config.InstallDir(), 56)
	siteName := orDash(cfg.SiteName)
	if siteName != "—" {
		siteName = strings.ToUpper(siteName)
	}

	ssdeepHashes := "—"
	if ssdeepInfo.Total > 0 {
		ssdeepHashes = fmt.Sprintf("%d hashes · %d shards", ssdeepInfo.Total, ssdeepInfo.Shards)
	} else if ssdeepInfo.Shards > 0 {
		ssdeepHashes = fmt.Sprintf("%d shards loaded", ssdeepInfo.Shards)
	}
	ssdeepVer := orDash(ssdeepInfo.Version)
	if ssdeepVer == "—" {
		ssdeepVer = orDash(st.SsdeepDBVersion)
	}

	statusPill := func(caption, value string, c color.Color) fyne.CanvasObject {
		val := heading(value, 14, c)
		return card(container.NewPadded(container.NewVBox(
			heading(caption, 9, colorMuted),
			vspace(2),
			val,
		)))
	}

	heroLeft := container.NewVBox(
		heading("Threat inSight", 22, colorText),
		vspace(4),
		muted("Endpoint protection · YARA + ssdeep"),
		vspace(10),
		container.NewHBox(
			card(container.NewPadded(heading("v"+version.AgentVersion, 12, colorAccentCyan))),
			hspace(8),
			card(container.NewPadded(heading("Agent "+orDash(status.AgentID), 12, colorText))),
		),
	)
	hero := card(container.NewPadded(container.NewBorder(nil, nil,
		container.NewCenter(img(resLogoAbout, 200, 72)),
		nil,
		container.NewPadded(heroLeft),
	)))

	pills := container.NewGridWithColumns(3,
		statusPill("CONNECTION", onlineLbl, onlineColor),
		statusPill("SCAN", scanningLbl, scanColor),
		statusPill("TI SYNC", shortStamp(st.LastTISyncRun), colorText),
	)

	deviceCard := card(container.NewPadded(container.NewVBox(
		sectionHeaderImg(resIconStat, "Device"),
		vspace(8),
		infoRow("Agent ID", orDash(status.AgentID)),
		divider(),
		infoRow("OS", truncateText(sysinfo.OsDescription(), 40)),
		divider(),
		infoRow("Edition", "Go agent"),
	)))

	yaraCount := fmt.Sprintf("%d", rulesInfo.Count)
	if rulesInfo.Count == 0 && rulesInfo.LocalCount > 0 {
		yaraCount = fmt.Sprintf("%d", rulesInfo.LocalCount)
	}

	rulesCard := card(container.NewPadded(container.NewVBox(
		sectionHeaderImg(resIconYara, "Threat intelligence"),
		vspace(8),
		infoRow("YARA version", truncateText(orDash(rulesInfo.Version), 28)),
		divider(),
		infoRow("YARA rules", yaraCount),
		divider(),
		infoRow("Ssdeep DB", truncateText(ssdeepVer, 28)),
		divider(),
		infoRow("Ssdeep loaded", ssdeepHashes),
		divider(),
		infoRow("Rules updated", truncateText(orDash(rulesInfo.UpdatedAt), 28)),
	)))

	siteCard := card(container.NewPadded(container.NewVBox(
		sectionHeaderImg(resIconConn, "Site"),
		vspace(8),
		infoRow("Name", truncateText(siteName, 40)),
		divider(),
		infoRow("Center", truncateText(orDash(cfg.SiteIP), 40)),
		divider(),
		infoRow("Site ID", truncateText(orDash(cfg.SiteID), 36)),
	)))

	pathsCard := card(container.NewPadded(container.NewVBox(
		sectionHeaderImg(resIconInfo, "Paths"),
		vspace(8),
		infoRow("Data", dataDir),
		divider(),
		infoRow("Install", installDir),
	)))

	grid := container.NewGridWithColumns(2, deviceCard, rulesCard, siteCard, pathsCard)

	body := container.NewVBox(
		hero,
		vspace(12),
		pills,
		vspace(12),
		grid,
		vspace(16),
		container.NewCenter(muted("© SOSECURE · Threat inSight")),
		vspace(8),
	)
	// flexWidth: fill the content pane, but never report a huge MinWidth.
	setPage(container.NewPadded(container.NewVScroll(container.New(&flexWidth{}, body))))
}

func shortStamp(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "—"
	}
	if len(t) >= 16 {
		if t[10] == 'T' {
			return strings.Replace(t[5:16], "T", " ", 1)
		}
		return t[5:16]
	}
	return t
}

// ---------------------------------------------------------------------------
// Custom widgets & helpers
// ---------------------------------------------------------------------------

const (
	sidebarW         = float32(72)
	sidebarIconSz    = float32(32)
	sidebarBtnSz     = float32(54)
	sidebarBtnRowH   = float32(64)
	sidebarBtnRadius = float32(12)
)

// navButton is a sidebar icon button with padded active/hover highlight.
type navButton struct {
	widget.BaseWidget
	res    fyne.Resource
	active bool
	hover  bool
	onTap  func()
	bg     *canvas.Rectangle
}

var (
	_ desktop.Hoverable = (*navButton)(nil)
	_ desktop.Cursorable = (*navButton)(nil)
)

func newNavButton(res fyne.Resource) *navButton {
	nb := &navButton{res: res, bg: canvas.NewRectangle(color.Transparent)}
	nb.ExtendBaseWidget(nb)
	return nb
}

func (n *navButton) Cursor() desktop.Cursor { return desktop.PointerCursor }

func (n *navButton) refreshBG() {
	switch {
	case n.active:
		n.bg.FillColor = colorPrimary
	case n.hover:
		n.bg.FillColor = color.NRGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0x38}
	default:
		n.bg.FillColor = color.Transparent
	}
	n.bg.Refresh()
}

func (n *navButton) setActive(a bool) {
	n.active = a
	n.refreshBG()
}

func (n *navButton) MouseIn(*desktop.MouseEvent) {
	n.hover = true
	n.refreshBG()
}

func (n *navButton) MouseMoved(*desktop.MouseEvent) {}

func (n *navButton) MouseOut() {
	n.hover = false
	n.refreshBG()
}

func (n *navButton) Tapped(*fyne.PointEvent) {
	if n.onTap != nil {
		n.onTap()
	}
}

func (n *navButton) CreateRenderer() fyne.WidgetRenderer {
	icon := canvas.NewImageFromResource(n.res)
	icon.FillMode = canvas.ImageFillContain
	icon.SetMinSize(fyne.NewSize(sidebarIconSz, sidebarIconSz))
	n.bg.CornerRadius = sidebarBtnRadius
	inner := container.NewStack(n.bg, container.NewCenter(icon))
	box := container.New(&fixedSize{w: sidebarBtnSz, h: sidebarBtnSz}, inner)
	return widget.NewSimpleRenderer(container.New(&fixedHeight{h: sidebarBtnRowH}, container.NewCenter(box)))
}

// scanActionButton is a scan control with border, hover, and press feedback.
type scanActionButton struct {
	widget.BaseWidget
	iconRes  fyne.Resource
	title    string
	primary  bool
	height   float32
	hover    bool
	press    bool
	disabled bool
	active   bool
	onTap    func()

	fill   *canvas.Rectangle
	border *canvas.Rectangle
	shade  *canvas.Rectangle
	titleT *canvas.Text
}

var (
	_ desktop.Hoverable  = (*scanActionButton)(nil)
	_ desktop.Cursorable = (*scanActionButton)(nil)
	_ desktop.Mouseable  = (*scanActionButton)(nil)
)

func newScanActionButton(icon fyne.Resource, title string, primary bool, height float32, onTap func()) *scanActionButton {
	b := &scanActionButton{
		iconRes: icon,
		title:   title,
		primary: primary,
		height:  height,
		onTap:   onTap,
		fill:    canvas.NewRectangle(colorCard),
		border:  canvas.NewRectangle(color.Transparent),
		shade:   canvas.NewRectangle(color.Transparent),
	}
	textSz := float32(16)
	fg := colorOnAccent
	if !primary {
		textSz = 13
		fg = colorText
	}
	b.titleT = heading(title, textSz, fg)
	b.ExtendBaseWidget(b)
	b.refreshLook()
	return b
}

func (b *scanActionButton) Cursor() desktop.Cursor {
	if b.disabled {
		return desktop.DefaultCursor
	}
	return desktop.PointerCursor
}

func (b *scanActionButton) setEnabled(on bool) {
	dis := !on
	if b.disabled == dis {
		return
	}
	b.disabled = dis
	if dis {
		b.hover = false
		b.press = false
	}
	b.refreshLook()
}

func (b *scanActionButton) setActive(on bool) {
	if b.active == on {
		return
	}
	b.active = on
	b.refreshLook()
}

func (b *scanActionButton) refreshLook() {
	radius := float32(12)
	if !b.primary {
		radius = 10
	}
	b.border.CornerRadius = radius
	b.fill.CornerRadius = radius
	b.shade.CornerRadius = radius

	switch {
	case b.disabled:
		b.shade.FillColor = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x55}
		b.press = false
		b.hover = false
	case b.press:
		b.shade.FillColor = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x35}
	case b.hover:
		b.shade.FillColor = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x14}
	default:
		b.shade.FillColor = color.Transparent
	}

	if b.primary {
		switch {
		case b.disabled:
			b.fill.FillColor = color.NRGBA{R: 0x1e, G: 0x3a, B: 0x5f, A: 0xff}
			b.border.StrokeColor = colorCardBorder
			b.border.StrokeWidth = 1
			if b.titleT != nil {
				b.titleT.Color = colorMuted
			}
		case b.press:
			b.fill.FillColor = color.NRGBA{R: 0x1d, G: 0x4e, B: 0xbd, A: 0xff}
			b.border.StrokeColor = colorAccentCyan
			b.border.StrokeWidth = 1.5
			if b.titleT != nil {
				b.titleT.Color = colorOnAccent
			}
		case b.hover || b.active:
			b.fill.FillColor = colorScanGradB
			b.border.StrokeColor = colorAccentCyan
			b.border.StrokeWidth = 1.5
			if b.titleT != nil {
				b.titleT.Color = colorOnAccent
			}
		default:
			b.fill.FillColor = colorScanGradA
			b.border.StrokeColor = color.NRGBA{R: 0x60, G: 0xa5, B: 0xfa, A: 0x70}
			b.border.StrokeWidth = 1
			if b.titleT != nil {
				b.titleT.Color = colorOnAccent
			}
		}
	} else {
		switch {
		case b.disabled:
			b.fill.FillColor = color.NRGBA{R: 0x15, G: 0x1c, B: 0x29, A: 0xff}
			b.border.StrokeColor = colorCardBorder
			b.border.StrokeWidth = 1
			if b.titleT != nil {
				b.titleT.Color = colorMuted
			}
		case b.active:
			b.fill.FillColor = color.NRGBA{R: 0x1e, G: 0x3a, B: 0x5f, A: 0xff}
			b.border.StrokeColor = colorAccentCyan
			b.border.StrokeWidth = 1.5
			if b.titleT != nil {
				b.titleT.Color = colorAccentCyan
			}
		case b.hover || b.press:
			b.fill.FillColor = color.NRGBA{R: 0x20, G: 0x2b, B: 0x3d, A: 0xff}
			b.border.StrokeColor = colorPrimary
			b.border.StrokeWidth = 1.5
			if b.titleT != nil {
				b.titleT.Color = colorText
			}
		default:
			b.fill.FillColor = colorCard
			b.border.StrokeColor = colorCardBorder
			b.border.StrokeWidth = 1
			if b.titleT != nil {
				b.titleT.Color = colorText
			}
		}
	}
	b.shade.Refresh()
	b.fill.Refresh()
	b.border.Refresh()
	if b.titleT != nil {
		b.titleT.Refresh()
	}
}

func (b *scanActionButton) MouseIn(*desktop.MouseEvent) {
	if b.disabled {
		return
	}
	b.hover = true
	b.refreshLook()
}

func (b *scanActionButton) MouseMoved(*desktop.MouseEvent) {}

func (b *scanActionButton) MouseOut() {
	b.hover = false
	b.press = false
	b.refreshLook()
}

func (b *scanActionButton) MouseDown(*desktop.MouseEvent) {
	if b.disabled {
		return
	}
	b.press = true
	b.refreshLook()
}

func (b *scanActionButton) MouseUp(*desktop.MouseEvent) {
	b.press = false
	b.refreshLook()
}

func (b *scanActionButton) Tapped(*fyne.PointEvent) {
	if b.disabled || b.onTap == nil {
		return
	}
	b.onTap()
}

func (b *scanActionButton) CreateRenderer() fyne.WidgetRenderer {
	iconSz := float32(26)
	if !b.primary {
		iconSz = 18
	}
	row := container.NewCenter(container.NewHBox(
		img(b.iconRes, iconSz, iconSz),
		hspace(8),
		b.titleT,
	))
	objects := []fyne.CanvasObject{b.fill, b.shade, b.border, row}
	stack := container.NewStack(objects...)
	return widget.NewSimpleRenderer(container.New(&fixedHeight{h: b.height}, stack))
}

// stopScanControl shows active (scanning) vs idle state; only fires when scanning.
type stopScanControl struct {
	widget.BaseWidget
	scanning bool
	hover    bool
	onTap    func()
	bg       *canvas.Rectangle
	label    *canvas.Text
	hint     *canvas.Text
}

var (
	_ desktop.Hoverable  = (*stopScanControl)(nil)
	_ desktop.Cursorable = (*stopScanControl)(nil)
)

func newStopScanControl(onTap func()) *stopScanControl {
	s := &stopScanControl{
		onTap: onTap,
		bg:    canvas.NewRectangle(color.NRGBA{R: 0x3f, G: 0x1d, B: 0x1d, A: 0xff}),
		label: heading("STOP SCAN", 13, colorMuted),
		hint:  canvasMuted("Available while scanning", colorMuted),
	}
	s.hint.TextSize = 10
	s.ExtendBaseWidget(s)
	s.refreshLook()
	return s
}

func (s *stopScanControl) setScanning(on bool) {
	if s.scanning == on {
		return
	}
	s.scanning = on
	s.hover = false
	s.refreshLook()
}

func (s *stopScanControl) Cursor() desktop.Cursor {
	if s.scanning {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

func (s *stopScanControl) refreshLook() {
	s.bg.CornerRadius = 22
	if s.scanning {
		switch {
		case s.hover:
			s.bg.FillColor = color.NRGBA{R: 0xf8, G: 0x71, B: 0x71, A: 0xff}
		default:
			s.bg.FillColor = colorError
		}
		s.label.Text = "STOP SCAN"
		s.label.Color = colorOnAccent
		s.hint.Text = "Tap to stop the running scan"
		s.hint.Color = color.NRGBA{R: 0xfc, G: 0xa5, B: 0xa5, A: 0xff}
	} else {
		s.bg.FillColor = color.NRGBA{R: 0x3f, G: 0x1d, B: 0x1d, A: 0xff}
		s.label.Text = "STOP SCAN"
		s.label.Color = colorMuted
		s.hint.Text = "Inactive — no scan running"
		s.hint.Color = colorMuted
	}
	s.bg.Refresh()
	s.label.Refresh()
	s.hint.Refresh()
}

func (s *stopScanControl) MouseIn(*desktop.MouseEvent) {
	if !s.scanning {
		return
	}
	s.hover = true
	s.refreshLook()
}

func (s *stopScanControl) MouseMoved(*desktop.MouseEvent) {}

func (s *stopScanControl) MouseOut() {
	s.hover = false
	s.refreshLook()
}

func (s *stopScanControl) Tapped(*fyne.PointEvent) {
	if !s.scanning || s.onTap == nil {
		return
	}
	s.onTap()
}

func (s *stopScanControl) CreateRenderer() fyne.WidgetRenderer {
	body := container.NewVBox(
		container.New(&fixedSize{w: 168, h: 45}, container.NewStack(s.bg, container.NewCenter(s.label))),
		vspace(4),
		container.NewCenter(s.hint),
	)
	return widget.NewSimpleRenderer(body)
}

// liveLogPanel wraps the activity list with a dark inset like legacy OverviewPage.
func liveLogPanel(list fyne.CanvasObject) fyne.CanvasObject {
	inner := canvas.NewRectangle(colorBg)
	inner.CornerRadius = 8
	head := heading("LIVE ACTIVITY LOG", 11, colorMuted)
	body := container.NewStack(inner, container.NewPadded(list))
	return container.NewBorder(
		container.NewVBox(head, vspace(8)),
		nil, nil, nil,
		body,
	)
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func truncateMiddle(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 4 || len(s) <= max {
		return s
	}
	keep := max - 1
	left := keep / 2
	right := keep - left
	if left < 1 {
		left = 1
	}
	if right < 1 {
		right = 1
	}
	return s[:left] + "…" + s[len(s)-right:]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func overviewScanModeLabel(scanType, source string) string {
	src := strings.TrimSpace(source)
	st := strings.ToLower(strings.TrimSpace(scanType))
	switch {
	case strings.EqualFold(src, "Realtime") || st == "silent":
		return "REALTIME"
	case strings.EqualFold(src, "Schedule"):
		return "SCHEDULE SCAN"
	case strings.EqualFold(src, "Login"):
		return "LOGIN SCAN"
	case strings.EqualFold(src, "USB"):
		return "USB SCAN"
	case st == "full":
		return "FULL SCAN"
	case st == "custom":
		return "CUSTOM SCAN"
	default:
		if src != "" {
			return strings.ToUpper(src) + " SCAN"
		}
		return "SCAN"
	}
}

func overviewEngineLabel(engine string) string {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "yara":
		return "YARA"
	case "ssdeep":
		return "ssdeep"
	case "discover":
		return "DISCOVER"
	default:
		return ""
	}
}

func liveScanLogEvent(ss ipc.ScanStatusResponse) *ipc.HistoryEvent {
	if !ss.Scanning {
		return nil
	}
	path := firstNonEmpty(ss.CurrentPath, ss.CurrentFile)
	eng := overviewEngineLabel(ss.CurrentEngine)
	if eng == "" && !ss.DiscoveryDone {
		eng = "DISCOVER"
	}
	msg := overviewScanModeLabel(ss.ScanType, ss.Source)
	if eng != "" {
		msg = eng + "  " + msg
	}
	if path != "" {
		msg += "  " + path
	} else if ss.Message != "" {
		msg += "  " + ss.Message
	}
	return &ipc.HistoryEvent{
		Time:    time.Now().Format(time.RFC3339),
		Kind:    "scan.live",
		Message: msg,
	}
}

// toolCardButton is a hoverable dashboard shortcut card.
type toolCardButton struct {
	widget.BaseWidget
	iconRes  fyne.Resource
	iconText string
	title    string
	hover    bool
	onTap    func()
	bg       *canvas.Rectangle
}

var (
	_ desktop.Hoverable  = (*toolCardButton)(nil)
	_ desktop.Cursorable = (*toolCardButton)(nil)
)

func newToolCardButton(icon fyne.Resource, text string, onTap func()) *toolCardButton {
	t := &toolCardButton{
		iconRes: icon,
		title:   text,
		onTap:   onTap,
		bg:      canvas.NewRectangle(colorCard),
	}
	t.bg.CornerRadius = 12
	t.bg.StrokeWidth = 1
	t.ExtendBaseWidget(t)
	t.refreshLook()
	return t
}

func newToolCardTextButton(iconText, text string, onTap func()) *toolCardButton {
	t := &toolCardButton{
		iconText: iconText,
		title:    text,
		onTap:    onTap,
		bg:       canvas.NewRectangle(colorCard),
	}
	t.bg.CornerRadius = 12
	t.bg.StrokeWidth = 1
	t.ExtendBaseWidget(t)
	t.refreshLook()
	return t
}

func (t *toolCardButton) Cursor() desktop.Cursor { return desktop.PointerCursor }

func (t *toolCardButton) refreshLook() {
	if t.hover {
		t.bg.FillColor = color.NRGBA{R: 0x1e, G: 0x29, B: 0x3b, A: 0xff}
		t.bg.StrokeColor = colorPrimary
	} else {
		t.bg.FillColor = colorCard
		t.bg.StrokeColor = colorCardBorder
	}
	t.bg.Refresh()
}

func (t *toolCardButton) MouseIn(*desktop.MouseEvent) {
	t.hover = true
	t.refreshLook()
}

func (t *toolCardButton) MouseMoved(*desktop.MouseEvent) {}

func (t *toolCardButton) MouseOut() {
	t.hover = false
	t.refreshLook()
}

func (t *toolCardButton) Tapped(*fyne.PointEvent) {
	if t.onTap != nil {
		t.onTap()
	}
}

func (t *toolCardButton) CreateRenderer() fyne.WidgetRenderer {
	var iconObj fyne.CanvasObject
	if t.iconText != "" {
		txt := heading(t.iconText, 20, colorPrimary)
		txt.Alignment = fyne.TextAlignCenter
		iconObj = container.NewCenter(container.New(&fixedHeight{h: 52}, txt))
	} else {
		iconObj = img(t.iconRes, 52, 52)
	}
	body := container.NewCenter(container.NewVBox(
		container.NewCenter(iconObj),
		vspace(10),
		container.NewCenter(heading(t.title, 13, colorText)),
	))
	return widget.NewSimpleRenderer(container.NewStack(t.bg, container.NewPadded(body)))
}

// toolCard is a large tappable card (VIEW LOGS / YARA / HASH).
func toolCard(icon fyne.Resource, text string, onTap func()) fyne.CanvasObject {
	return newToolCardButton(icon, text, onTap)
}

// toolCardText is like toolCard but uses lettering for the icon (e.g. "ssdeep").
func toolCardText(iconText, text string, onTap func()) fyne.CanvasObject {
	return newToolCardTextButton(iconText, text, onTap)
}

func sectionHeaderImg(icon fyne.Resource, text string) fyne.CanvasObject {
	return container.NewHBox(img(icon, 18, 18), hspace(4), heading(text, 15, colorText))
}

func toggleRowImg(icon fyne.Resource, title, sub string, check *widget.Check) fyne.CanvasObject {
	left := container.NewHBox(img(icon, 22, 22), hspace(8), container.NewVBox(label(title), muted(sub)))
	return container.NewBorder(nil, nil, left, container.NewCenter(check))
}

// progressRing draws a circular progress meter via a raster.
type progressRing struct {
	canvas *canvas.Raster
	frac   float64
}

func newProgressRing() *progressRing {
	pr := &progressRing{}
	pr.canvas = canvas.NewRaster(func(w, h int) image.Image { return drawRing(w, h, pr.frac) })
	return pr
}

func (pr *progressRing) set(f float64) {
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	pr.frac = f
	canvas.Refresh(pr.canvas)
}

func drawRing(w, h int, frac float64) image.Image {
	imgOut := image.NewRGBA(image.Rect(0, 0, w, h))
	if w == 0 || h == 0 {
		return imgOut
	}
	cx, cy := float64(w)/2, float64(h)/2
	rad := math.Min(cx, cy) - 2
	thick := rad * 0.18
	track := color.NRGBA{R: 0x33, G: 0x41, B: 0x55, A: 0xff}
	prog := colorPrimary
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			dist := math.Hypot(dx, dy)
			if dist > rad || dist < rad-thick {
				continue
			}
			ang := math.Atan2(dx, -dy) // 0 at top, clockwise
			if ang < 0 {
				ang += 2 * math.Pi
			}
			if ang/(2*math.Pi) <= frac {
				imgOut.Set(x, y, prog)
			} else {
				imgOut.Set(x, y, track)
			}
		}
	}
	return imgOut
}

// runThreatIntelSyncUI starts an async server sync and shows a progress dialog
// until the service reports sync_busy=false.
func (r *Router) runThreatIntelSyncUI(onDone func(err error, msg string)) {
	msg := canvasMuted("Starting sync…", colorMuted)
	bar := widget.NewProgressBar()
	bar.Min = 0
	bar.Max = 100
	bar.SetValue(0)
	body := container.NewVBox(msg, vspace(10), bar)
	d := dialog.NewCustomWithoutButtons("Syncing threat intelligence", container.NewPadded(body), r.window)
	d.Resize(fyne.NewSize(440, 150))
	d.Show()

	if err := r.client.SyncRules(r.ctx); err != nil {
		d.Hide()
		onDone(err, "")
		return
	}

	go func() {
		seenBusy := false
		deadline := time.Now().Add(45 * time.Minute)
		var lastMsg string
		for time.Now().Before(deadline) {
			st, err := r.client.Status(r.ctx)
			if err == nil {
				lastMsg = strings.TrimSpace(st.DownloadMessage)
				pct := st.DownloadPercent
				busy := st.SyncBusy
				fyne.Do(func() {
					bar.SetValue(pct)
					if lastMsg != "" {
						msg.Text = humanizeNotifyMessage(lastMsg)
						msg.Refresh()
					}
				})
				if busy {
					seenBusy = true
				}
				done := (seenBusy && !busy) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "sync done")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "sync failed")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "sync queued")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "waiting until the current scan finishes")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "threat intelligence is up to date")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "threat intelligence updated")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "threat intelligence sync finished"))
				if done {
					failed := strings.Contains(strings.ToLower(lastMsg), "sync failed")
					display := humanizeNotifyMessage(lastMsg)
					fyne.Do(func() {
						if !failed {
							bar.SetValue(100)
						}
						d.Hide()
						if failed {
							onDone(fmt.Errorf("%s", display), display)
							return
						}
						onDone(nil, display)
					})
					return
				}
			}
			time.Sleep(400 * time.Millisecond)
		}
		fyne.Do(func() {
			d.Hide()
			onDone(fmt.Errorf("sync timed out"), lastMsg)
		})
	}()
}

var _ = fmt.Sprintf
