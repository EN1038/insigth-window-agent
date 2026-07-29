//go:build windows

package ui

import (
	"fmt"
	"image"
	"image/color"
	"math"
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
	"github.com/sosecure/insite-agent/internal/sysinfo"
)

// ---------------------------------------------------------------------------
// Main window: 65px icon sidebar + header stats + page host + footer
// ---------------------------------------------------------------------------

func (r *Router) showMain() {
	r.stopTicker()
	r.window.SetPadded(false)
	r.window.Resize(fyne.NewSize(1100, 650))
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
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-t.C:
				refreshHeader()
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
	closeBtn := chromeCloseButton(func() { r.window.Hide() })
	drag := container.NewMax(newDragBar(func() uintptr { return r.windowHWND() }))
	return draggableTopBar(bg, 36, hspace(1), closeBtn, drag)
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
	fullScan := newScanActionButton(resIconScan, "FULL SCAN", true, 80, func() {
		resp, err := r.client.StartScan(r.ctx, "full", "")
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
	})
	customScan := newScanActionButton(resIconSet, "CUSTOM SCAN", false, 50, func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			resp, e := r.client.StartScan(r.ctx, "custom", u.Path())
			if e != nil {
				dialog.ShowError(e, r.window)
				return
			}
			if !resp.OK {
				msg := resp.Message
				if strings.TrimSpace(msg) == "" {
					msg = "Cannot start scan"
				}
				dialog.ShowInformation("Scan", msg, r.window)
			}
		}, r.window)
	})

	typeGroup := widget.NewRadioGroup([]string{"REAL TIME", "ON-DEMAND"}, func(string) {})
	typeGroup.Horizontal = false
	typeGroup.SetSelected("REAL TIME")

	stopCtrl := newStopScanControl(func() { _ = r.client.StopScan(r.ctx) })

	leftCol := container.NewVBox(
		fullScan,
		vspace(14),
		customScan,
		vspace(20),
		container.NewCenter(heading("TYPE SCAN", 10, colorMuted)),
		vspace(8),
		container.NewCenter(container.New(&fixedWidth{w: 200}, typeGroup)),
		vspace(14),
		container.NewCenter(stopCtrl),
	)
	leftScroll := container.NewVScroll(leftCol)
	const overviewH = float32(488)
	leftPanel := card(container.New(&fixedHeight{h: overviewH}, leftScroll))

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
	pctBox := container.NewStack(
		container.New(&fixedSize{w: 200, h: 200}, ring.canvas),
		container.NewCenter(container.NewVBox(
			container.NewCenter(pct),
			container.NewCenter(canvasMuted("%", colorMuted)),
		)),
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
			msg.Text = truncateText(e.Message, 72)
			msg.Color = kindColor(e.Kind)
			ts.Refresh()
			msg.Refresh()
		},
	)
	logPanel := liveLogPanel(logList)

	rightCardBody := container.NewHBox(
		container.New(&fixedWidth{w: 140}, metrics),
		container.New(&fixedWidth{w: 240}, container.NewCenter(pctBox)),
		layout.NewSpacer(),
		container.New(&fixedWidth{w: 300}, logPanel),
	)
	rightCard := card(container.NewPadded(container.NewPadded(rightCardBody)))

	tools := container.NewGridWithColumns(3,
		toolCard(resIconLog, "VIEW LOGS", func() { r.showViewLogs() }),
		toolCard(resIconYara, "YARA RULES", func() { r.showYaraRules() }),
		toolCard(resIconHash, "HASH", func() { r.showHashTool() }),
	)

	rightCol := container.NewVBox(
		rightCard,
		vspace(12),
		container.New(&fixedHeight{h: 132}, tools),
	)

	page := container.NewBorder(nil, nil,
		container.New(&fixedWidth{w: 248}, container.New(&fixedHeight{h: overviewH}, leftPanel)),
		nil,
		container.New(&fixedHeight{h: overviewH}, container.NewPadded(rightCol)),
	)
	setPage(container.NewPadded(page))

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
			fileCount.Text = fmtCount(ss.Scanned)
			detectCount.Text = fmtCount(ss.Threats)
			frac := 0.0
			if ss.Total > 0 {
				frac = float64(ss.Scanned) / float64(ss.Total)
			} else if !ss.Scanning {
				frac = 0
			}
			ring.set(frac)
			pct.Text = fmtCount(int(frac * 100))
			fileCount.Refresh()
			detectCount.Refresh()
			pct.Refresh()
			stopCtrl.setScanning(ss.Scanning)
			if evErr == nil {
				logEvents = filterScanEvents(ev, 40)
				logList.Refresh()
			}
		})
	}
	go func() {
		refresh()
		t := time.NewTicker(2 * time.Second)
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

	batch := widget.NewEntry()
	batch.SetText(st.BatchJobEveryDay)
	batch.SetPlaceHolder("HH:mm")

	tiSync := widget.NewEntry()
	tiSync.SetText(st.TISyncEveryDay)
	tiSync.SetPlaceHolder("HH:mm")

	excl := widget.NewMultiLineEntry()
	excl.SetText(st.ExclusionPaths)
	excl.SetMinRowsVisible(3)

	scanExt := widget.NewMultiLineEntry()
	scanExt.SetText(st.ScanExtensions)
	scanExt.SetMinRowsVisible(3)

	quick := widget.NewMultiLineEntry()
	quick.SetText(st.QuickScanPaths)
	quick.SetMinRowsVisible(2)

	ssdeepOn := widget.NewCheck("", nil)
	ssdeepOn.SetChecked(st.SsdeepEnabled)
	ssdeepReport := widget.NewCheck("", nil)
	ssdeepReport.SetChecked(st.SsdeepReportAPI)
	quarantine := widget.NewCheck("", nil)
	quarantine.SetChecked(st.QuarantineOnDetect)
	sendCand := widget.NewCheck("", nil)
	sendCand.SetChecked(st.SendSsdeepCandidate)

	threshold := widget.NewEntry()
	threshold.SetText(st.SsdeepThreshold)
	threshold.SetPlaceHolder("85")

	logLevel := widget.NewEntry()
	logLevel.SetText(st.LogLevel)
	cacheHours := widget.NewEntry()
	cacheHours.SetText(st.CacheExpiryHours)

	protection := card(container.NewVBox(
		sectionHeaderImg(resIconRT, "Protection"),
		vspace(4),
		toggleRowImg(resIconRT, "Real-time protection", "Scan files the moment they are accessed", rt),
		divider(),
		toggleRowImg(resIconUSB, "USB protection", "Automatically scan removable drives", usb),
		divider(),
		toggleRowImg(resIconConn, "Auto scan on login", "Run a quick scan when a user signs in", auto),
	))

	schedule := card(container.NewVBox(
		sectionHeaderImg(resIconBatch, "Scheduled scan & scope"),
		vspace(4),
		fieldLabel("Daily batch scan time (HH:mm)"),
		batch,
		vspace(8),
		fieldLabel("Daily threat intelligence sync (rules + ssdeep, HH:mm)"),
		tiSync,
		vspace(8),
		fieldLabel("Excluded paths (one per line)"),
		excl,
		vspace(8),
		fieldLabel("Scan extensions (comma-separated)"),
		scanExt,
		vspace(8),
		fieldLabel("Quick scan paths (one per line)"),
		quick,
	))

	ssdeepCard := card(container.NewVBox(
		sectionHeaderImg(resIconYara, "Ssdeep"),
		vspace(4),
		toggleRowImg(resIconYara, "Ssdeep engine", "Fuzzy-hash secondary scanner", ssdeepOn),
		divider(),
		fieldLabel("Match threshold (0–100)"),
		threshold,
		vspace(6),
		toggleRowImg(resIconConn, "Report detections to API", "POST sendLogSsdeep", ssdeepReport),
		divider(),
		toggleRowImg(resIconConn, "Quarantine on detect", "Isolate matched files", quarantine),
		divider(),
		toggleRowImg(resIconConn, "Send ssdeep candidate", "Queue unknown samples", sendCand),
	))

	advanced := card(container.NewVBox(
		sectionHeaderImg(resIconSet, "Advanced"),
		vspace(4),
		fieldLabel("Log level"),
		logLevel,
		vspace(6),
		fieldLabel("Cache expiry (hours)"),
		cacheHours,
	))

	rulesVer := muted("Version " + orDash(st.RulesVersion))
	syncBtn := widget.NewButtonWithIcon("Sync now", theme.DownloadIcon(), nil)
	syncBtn.OnTapped = func() {
		syncBtn.Disable()
		r.runThreatIntelSyncUI(func(err error, msg string) {
			syncBtn.Enable()
			if err != nil {
				dialog.ShowError(err, r.window)
				return
			}
			// Reload settings page so Center values appear without leaving the page.
			r.showSettings(setPage)
			if strings.TrimSpace(msg) == "" {
				msg = "Synced rules, ssdeep, and settings from server."
			}
			dialog.ShowInformation("Threat intelligence", msg, r.window)
		})
	}
	rulesCard := card(container.NewVBox(
		sectionHeaderImg(resIconYara, "Threat intelligence"),
		vspace(4),
		container.NewBorder(nil, nil, container.NewVBox(label("Threat rules"), rulesVer), syncBtn),
	))

	save := widget.NewButtonWithIcon("Save settings", theme.DocumentSaveIcon(), func() {
		if err := r.client.UpdateSettings(r.ctx, ipc.UpdateSettingsRequest{
			RealtimeShield:      boolPtr(rt.Checked),
			USBProtection:       boolPtr(usb.Checked),
			AutoScanOnLogin:     boolPtr(auto.Checked),
			BatchJobEveryDay:    batch.Text,
			TISyncEveryDay:      tiSync.Text,
			ExclusionPaths:      excl.Text,
			ScanExtensions:      scanExt.Text,
			QuickScanPaths:      quick.Text,
			SsdeepEnabled:       boolPtr(ssdeepOn.Checked),
			SsdeepThreshold:     threshold.Text,
			SsdeepReportAPI:     boolPtr(ssdeepReport.Checked),
			QuarantineOnDetect:  boolPtr(quarantine.Checked),
			SendSsdeepCandidate: boolPtr(sendCand.Checked),
			LogLevel:            logLevel.Text,
			CacheExpiryHours:    cacheHours.Text,
		}); err != nil {
			dialog.ShowError(err, r.window)
			return
		}
		dialog.ShowInformation("Saved", "Your settings have been updated.", r.window)
	})
	save.Importance = widget.HighImportance

	logout := widget.NewButtonWithIcon("Sign out", theme.LogoutIcon(), func() {
		dialog.ShowConfirm("Sign out", "Sign out of this agent?", func(ok bool) {
			if !ok {
				return
			}
			_ = r.client.Logout(r.ctx)
			r.showLogin()
		}, r.window)
	})
	logout.Importance = widget.DangerImportance

	body := container.NewVBox(
		protection, vspace(6),
		schedule, vspace(6),
		ssdeepCard, vspace(6),
		advanced, vspace(6),
		rulesCard, vspace(6),
		container.NewGridWithColumns(2, logout, save),
	)
	setPage(container.NewPadded(container.NewVScroll(body)))
}

// ---------------------------------------------------------------------------
// About page  ->  matches AboutPage.xaml
// ---------------------------------------------------------------------------

func (r *Router) showAbout(setPage func(fyne.CanvasObject)) {
	status, _ := r.client.Status(r.ctx)
	cfg, _ := r.client.GetConfig(r.ctx)
	rulesInfo, _ := r.client.RulesInfo(r.ctx)
	scan, _ := r.client.ScanStatus(r.ctx)

	online := "OFFLINE"
	if status.Online {
		online = "ONLINE"
	}
	scanning := "IDLE"
	if scan.Scanning {
		scanning = "SCANNING (" + titleCase(scan.ScanType) + ")"
	}

	dataDir := config.DataBaseDir()
	installDir := config.InstallDir()

	body := container.NewVBox(
		vspace(10),
		container.NewCenter(img(resLogoAbout, 300, 110)),
		vspace(12),
		card(container.NewVBox(
			sectionHeaderImg(resIconStat, "Device & status"),
			vspace(6),
			infoRow("Agent ID", orDash(status.AgentID)),
			divider(),
			infoRow("Connection", online),
			divider(),
			infoRow("Scan", scanning),
		)),
		vspace(10),
		card(container.NewVBox(
			sectionHeaderImg(resIconYara, "Threat rules"),
			vspace(6),
			infoRow("Rules version", orDash(rulesInfo.Version)),
			divider(),
			infoRow("Rules count", fmt.Sprintf("%d", rulesInfo.Count)),
			divider(),
			infoRow("Updated at", orDash(rulesInfo.UpdatedAt)),
		)),
		vspace(10),
		card(container.NewVBox(
			sectionHeaderImg(resIconConn, "Site config"),
			vspace(6),
			infoRow("Site name", orDash(cfg.SiteName)),
			divider(),
			infoRow("Site IP", orDash(cfg.SiteIP)),
			divider(),
			infoRow("Site ID", orDash(cfg.SiteID)),
		)),
		vspace(10),
		card(container.NewVBox(
			sectionHeaderImg(resIconInfo, "About"),
			vspace(6),
			infoRow("Edition", "Go rewrite"),
			divider(),
			infoRow("Platform", "Windows Server 2012 R2 and newer"),
			divider(),
			infoRow("Engine", "YARA rules + real-time monitor"),
			divider(),
			infoRow("Version", "4"),
			divider(),
			infoRow("Data directory", dataDir),
			divider(),
			infoRow("Install directory", installDir),
		)),
		vspace(16),
		container.NewCenter(muted("© SOSECURE · Threat inSight")),
	)
	setPage(container.NewPadded(container.NewVScroll(container.NewCenter(container.New(&fixedWidth{w: 460}, body)))))
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
	iconRes fyne.Resource
	title   string
	primary bool
	height  float32
	hover   bool
	press   bool
	onTap   func()

	fill   *canvas.Rectangle
	border *canvas.Rectangle
	shade  *canvas.Rectangle
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
	b.ExtendBaseWidget(b)
	b.refreshLook()
	return b
}

func (b *scanActionButton) Cursor() desktop.Cursor { return desktop.PointerCursor }

func (b *scanActionButton) refreshLook() {
	radius := float32(12)
	if !b.primary {
		radius = 10
	}
	b.border.CornerRadius = radius
	b.fill.CornerRadius = radius
	b.shade.CornerRadius = radius

	switch {
	case b.press:
		b.shade.FillColor = color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x35}
	case b.hover:
		b.shade.FillColor = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0x14}
	default:
		b.shade.FillColor = color.Transparent
	}

	if b.primary {
		switch {
		case b.press:
			b.fill.FillColor = color.NRGBA{R: 0x1d, G: 0x4e, B: 0xbd, A: 0xff}
		case b.hover:
			b.fill.FillColor = colorScanGradB
		default:
			b.fill.FillColor = colorScanGradA
		}
		if b.hover || b.press {
			b.border.StrokeColor = colorAccentCyan
			b.border.StrokeWidth = 1.5
		} else {
			b.border.StrokeColor = color.NRGBA{R: 0x60, G: 0xa5, B: 0xfa, A: 0x70}
			b.border.StrokeWidth = 1
		}
	} else {
		if b.hover || b.press {
			b.fill.FillColor = color.NRGBA{R: 0x20, G: 0x2b, B: 0x3d, A: 0xff}
			b.border.StrokeColor = colorPrimary
			b.border.StrokeWidth = 1.5
		} else {
			b.fill.FillColor = colorCard
			b.border.StrokeColor = colorCardBorder
			b.border.StrokeWidth = 1
		}
	}
	b.shade.Refresh()
	b.fill.Refresh()
	b.border.Refresh()
}

func (b *scanActionButton) MouseIn(*desktop.MouseEvent) {
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
	b.press = true
	b.refreshLook()
}

func (b *scanActionButton) MouseUp(*desktop.MouseEvent) {
	b.press = false
	b.refreshLook()
}

func (b *scanActionButton) Tapped(*fyne.PointEvent) {
	if b.onTap != nil {
		b.onTap()
	}
}

func (b *scanActionButton) CreateRenderer() fyne.WidgetRenderer {
	iconSz := float32(26)
	textSz := float32(16)
	if !b.primary {
		iconSz = 18
		textSz = 13
	}
	row := container.NewCenter(container.NewHBox(
		img(b.iconRes, iconSz, iconSz),
		hspace(8),
		heading(b.title, textSz, colorOnAccent),
	))
	if !b.primary {
		row = container.NewCenter(container.NewHBox(
			img(b.iconRes, iconSz, iconSz),
			hspace(8),
			heading(b.title, textSz, colorText),
		))
	}
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
		container.New(&fixedHeight{h: 248}, body),
	)
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// toolCardButton is a hoverable dashboard shortcut card.
type toolCardButton struct {
	widget.BaseWidget
	iconRes fyne.Resource
	title   string
	hover   bool
	onTap   func()
	bg      *canvas.Rectangle
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
	body := container.NewCenter(container.NewVBox(
		container.NewCenter(img(t.iconRes, 52, 52)),
		vspace(10),
		container.NewCenter(heading(t.title, 13, colorText)),
	))
	return widget.NewSimpleRenderer(container.NewStack(t.bg, container.NewPadded(body)))
}

// toolCard is a large tappable card (VIEW LOGS / YARA / HASH).
func toolCard(icon fyne.Resource, text string, onTap func()) fyne.CanvasObject {
	return newToolCardButton(icon, text, onTap)
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
						msg.Text = lastMsg
						msg.Refresh()
					}
				})
				if busy {
					seenBusy = true
				}
				done := (seenBusy && !busy) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "sync done")) ||
					(!busy && strings.Contains(strings.ToLower(lastMsg), "sync failed"))
				if done {
					failed := strings.Contains(strings.ToLower(lastMsg), "sync failed")
					fyne.Do(func() {
						if !failed {
							bar.SetValue(100)
						}
						d.Hide()
						if failed {
							onDone(fmt.Errorf("%s", lastMsg), lastMsg)
							return
						}
						onDone(nil, lastMsg)
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
