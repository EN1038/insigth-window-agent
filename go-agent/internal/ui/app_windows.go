//go:build windows

package ui

import (
	"context"
	"fmt"
	"image/color"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/ipc"
)

const appTitle = "SOSECURE Threat inSight"

// Run displays the UI. embedded is true when the UI had to start its own
// in-process host because the background service was not running.
func Run(ctx context.Context, client *ipc.Client, embedded bool) error {
	release, ok := tryAcquireUISingleton()
	if !ok {
		// Another UI is already running — just ask it to show, do not add another tray icon.
		_ = requestUIShow()
		return nil
	}
	defer release()

	prepareSoftwareGL()
	a := app.NewWithID("com.sosecure.insite-agent")
	a.Settings().SetTheme(insiteTheme{})
	a.SetIcon(resIconMain)

	w := newChromeWindow(a, appTitle)
	w.SetIcon(resIconMain)
	w.Resize(fyne.NewSize(800, 480))
	w.CenterOnScreen()

	r := &Router{app: a, window: w, client: client, ctx: ctx, embedded: embedded}
	startHWNDCache(w, &r.hwnd, appTitle)
	r.setupTrayAndCloseBehavior()
	r.showFlow()

	if embedded {
		go func() {
			time.Sleep(700 * time.Millisecond)
			fyne.Do(func() {
				dialog.ShowInformation(
					"Background service not running",
					"Running in standalone mode inside this window.\n"+
						"Real-time protection runs only while this window stays open.\n\n"+
						"Start the \""+appTitle+"\" Windows service for always-on protection.",
					w,
				)
			})
		}()
	}
	w.ShowAndRun()
	return nil
}

type Router struct {
	app      fyne.App
	window   fyne.Window
	client   *ipc.Client
	ctx      context.Context
	embedded bool

	stopRefresh chan struct{}
	hwnd        atomic.Uintptr
}

func (r *Router) setupTrayAndCloseBehavior() {
	// System tray: left-click shows window (Fyne 2.7+); right-click opens menu.
	// Tray menu callbacks must NOT call Fyne window APIs directly (deadlocks).
	if desk, ok := r.app.(desktop.App); ok {
		openItem := fyne.NewMenuItem("Open", func() {
			_ = requestUIShow()
			r.forceShowNative()
		})
		exitItem := fyne.NewMenuItem("Exit", func() {
			_ = launchConfirmExit()
		})
		exitItem.IsQuit = true
		desk.SetSystemTrayMenu(fyne.NewMenu("", openItem, fyne.NewMenuItemSeparator(), exitItem))
		desk.SetSystemTrayIcon(resIconMain)
		desk.SetSystemTrayWindow(r.window)
	}

	// Close / ✕ hide to tray (do not destroy the window).
	r.window.SetCloseIntercept(func() {
		r.window.Hide()
	})

	go r.traySignalPump()
}

// traySignalPump handles Open/Exit requests from the tray without touching Fyne
// APIs on the systray callback goroutine.
func (r *Router) traySignalPump() {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			if consumeUISignal(uiShowSignal) {
				fyne.Do(func() {
					r.window.Show()
					r.window.RequestFocus()
					if c := r.window.Content(); c != nil {
						c.Show()
					}
				})
				time.Sleep(80 * time.Millisecond)
				r.forceShowNative()
			}
			if consumeUISignal(uiQuitSignal) {
				fyne.Do(func() {
					r.window.SetCloseIntercept(nil)
					r.window.Close()
					r.app.Quit()
				})
				return
			}
		}
	}
}

// stopTicker halts any running page refresh loop.
func (r *Router) stopTicker() {
	if r.stopRefresh != nil {
		close(r.stopRefresh)
		r.stopRefresh = nil
	}
}

func (r *Router) showFlow() {
	r.stopTicker()
	st, err := r.client.Status(r.ctx)
	if err != nil {
		r.window.SetContent(r.errorScreen("Cannot reach the agent service.\n" + err.Error()))
		return
	}
	switch {
	case !st.HasConfig:
		r.showConfig()
	case !st.Approved:
		r.showApproval()
	case !st.LoggedIn:
		r.showLogin()
	default:
		r.showMain()
	}
}

// ---------------------------------------------------------------------------
// Shared chrome (auth screens): top bar + right backdrop + bottom status bar
// ---------------------------------------------------------------------------

// authScreen composes the branded 800x480 layout: full-window backdrop, a dark
// top bar (menu + close + drag), the form column on the left, and status bar.
func (r *Router) authScreen(form fyne.CanvasObject, showConn bool) fyne.CanvasObject {
	// Do not call window.Resize here: tray handlers may already be on the UI
	// thread via RunNative, and Resize re-enters runOnMain (deadlock).
	r.window.SetPadded(false)

	top := r.authTopBar()
	bottom, startConn := r.authBottomBar(showConn)

	backdrop := authBackground()
	// Left-side scrim keeps form text readable over the bright artwork.
	scrim := canvas.NewLinearGradient(
		color.NRGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 0xf0},
		color.NRGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 0x00},
		0,
	)

	formCol := container.New(&fixedWidth{w: 340}, form)
	// Match legacy ConfigWindow/LoginWindow left margin (~40px).
	leftCol := container.NewHBox(hspace(48), formCol)
	overlay := container.NewBorder(nil, nil,
		container.NewVBox(vspace(24), leftCol),
		nil,
		layout.NewSpacer(),
	)

	// Background spans the entire window (legacy Grid + UniformToFill), with bars overlaid.
	base := canvas.NewRectangle(colorBg)
	foreground := container.NewBorder(top, bottom, nil, nil, overlay)
	screen := container.NewStack(base, backdrop, scrim, foreground)

	if startConn != nil {
		startConn()
	}
	return screen
}

func (r *Router) windowHWND() uintptr { return r.hwnd.Load() }

func (r *Router) authTopBar() fyne.CanvasObject {
	bg := canvas.NewRectangle(color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xcc})
	bg.SetMinSize(fyne.NewSize(10, 40))

	menuBtn := chromeMenuButton(func() { r.showAppMenu() })
	left := container.NewHBox(hspace(4), menuBtn)

	// Hide (not Close): Close destroys the window and leaves a dead tray icon that Open cannot restore.
	closeBtn := chromeCloseButton(func() { r.window.Hide() })
	drag := container.NewMax(newDragBar(func() uintptr { return r.windowHWND() }))

	return draggableTopBar(bg, 40, left, closeBtn, drag)
}

// authBottomBar returns the status bar plus an optional starter that begins the
// live connection poller for the "Connection: ● Offline/Online" indicator.
func (r *Router) authBottomBar(showConn bool) (fyne.CanvasObject, func()) {
	bg := canvas.NewRectangle(color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xe6})
	bg.SetMinSize(fyne.NewSize(10, 34))

	poweredBy := container.NewHBox(
		canvasMuted("Powered By : ", colorText),
		heading("SOSECURE", 12, colorAccentCyan),
	)
	version := canvasMuted("Version : 4", colorMuted)

	var left fyne.CanvasObject
	var starter func()
	if showConn {
		dot := statusDot(colorError, 11)
		lbl := canvasMuted("Offline", colorText)
		left = container.NewHBox(canvasMuted("Connection : ", colorText), container.NewCenter(dot), hspace(4), lbl)
		starter = func() { r.pollConnection(dot, lbl) }
	} else {
		left = hspace(1)
	}

	row := container.NewBorder(nil, nil,
		container.NewHBox(hspace(6), container.NewCenter(left)),
		container.NewHBox(container.NewCenter(version), hspace(6)),
		container.NewCenter(poweredBy),
	)
	return container.NewStack(bg, container.NewVBox(layout.NewSpacer(), row, layout.NewSpacer())), starter
}

// pollConnection updates a status dot/label from the server reachability probe.
func (r *Router) pollConnection(dot *sizedCircle, lbl *canvas.Text) {
	stop := make(chan struct{})
	r.stopRefresh = stop
	update := func() {
		ok, _ := r.client.TestConnection(r.ctx)
		fyne.Do(func() {
			if ok {
				dot.FillColor = colorStatusGrn
				lbl.Text = "Online"
			} else {
				dot.FillColor = colorError
				lbl.Text = "Offline"
			}
			dot.Refresh()
			lbl.Refresh()
		})
	}
	go func() {
		update()
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				update()
			}
		}
	}()
}

func (r *Router) showAppMenu() {
	items := []*fyne.MenuItem{
		fyne.NewMenuItem("Change Server Settings", func() { r.showConfig() }),
		fyne.NewMenuItem("About SOSECURE", func() { r.showAboutDialog() }),
	}
	m := fyne.NewMenu("", items...)
	widget.ShowPopUpMenuAtPosition(m, r.window.Canvas(), fyne.NewPos(16, 42))
}

func (r *Router) showAboutDialog() {
	body := container.NewVBox(
		container.NewCenter(img(resLogoAbout, 240, 90)),
		vspace(6),
		container.NewCenter(muted("Endpoint threat detection agent")),
		container.NewCenter(muted("Edition: Go rewrite  ·  Version 4")),
		container.NewCenter(muted("© SOSECURE · Threat inSight")),
	)
	dialog.ShowCustom("About SOSECURE", "Close", container.NewPadded(body), r.window)
}

func (r *Router) errorScreen(msg string) fyne.CanvasObject {
	body := container.NewVBox(
		container.NewCenter(img(resLogoFull, 220, 70)),
		vspace(14),
		container.NewCenter(heading("Service unavailable", 18, colorText)),
		vspace(4),
		container.NewCenter(widget.NewLabelWithStyle(msg, fyne.TextAlignCenter, fyne.TextStyle{})),
		vspace(14),
	)
	retry := widget.NewButtonWithIcon("Retry connection", theme.ViewRefreshIcon(), func() { r.showFlow() })
	retry.Importance = widget.HighImportance
	body.Add(retry)
	return r.authScreen(body, false)
}

// ---------------------------------------------------------------------------
// Config (Server IP / Site Code / Site Key)  ->  matches ConfigWindow.xaml
// ---------------------------------------------------------------------------

func (r *Router) showConfig() {
	r.stopTicker()
	r.window.Resize(fyne.NewSize(800, 480))

	ipEntry := newPlainEntry()
	ipEntry.SetPlaceHolder("http://server.example.com")
	codeEntry := newPlainEntry()
	codeEntry.SetPlaceHolder("Your site code")
	keyEntry := newPlainPassword()
	keyEntry.SetPlaceHolder("Site key (token)")

	// Always start blank — user must enter Server IP, Site Code, and Site Key step by step.
	status := canvasMuted("Enter Server IP, Site Code, and Site Key to continue", colorMuted)

	saveBtn := widget.NewButton("SAVE & CONNECT", func() {
		siteIP := strings.TrimSpace(ipEntry.Text)
		siteID := strings.TrimSpace(codeEntry.Text)
		siteKey := strings.TrimSpace(keyEntry.Text)
		if siteIP == "" || siteID == "" || siteKey == "" {
			status.Text = "Please fill Server IP, Site Code, and Site Key"
			status.Color = colorError
			status.Refresh()
			return
		}
		resp, err := r.client.SaveConfig(r.ctx, ipc.SaveConfigRequest{
			SiteIP:  siteIP,
			SiteID:  siteID,
			SiteKey: siteKey,
		})
		if err != nil || !resp.OK {
			msg := "Save failed"
			if err != nil {
				msg = err.Error()
			} else if resp.Message != "" {
				msg = resp.Message
			}
			status.Text = msg
			status.Color = colorError
			status.Refresh()
			return
		}
		r.showApproval()
	})
	saveBtn.Importance = widget.HighImportance

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(24),
		fieldLabel("Server IP"),
		authField(ipEntry),
		vspace(12),
		fieldLabel("Site Code"),
		authField(codeEntry),
		vspace(12),
		fieldLabel("Site Key (Token)"),
		authField(keyEntry),
		vspace(20),
		tallButton(saveBtn),
		vspace(8),
		status,
	)
	r.window.SetContent(r.authScreen(form, true))
}

// ---------------------------------------------------------------------------
// Loading / approval  ->  matches WaitingApprovalWindow.xaml
// ---------------------------------------------------------------------------

func (r *Router) showApproval() {
	r.stopTicker()
	r.window.Resize(fyne.NewSize(800, 480))

	spinner := widget.NewActivity()
	spinner.Start()

	statusText := heading("Registering device info to server...", 16, colorText)
	sub := canvasMuted("Waiting for administrator approval to activate this device.", colorMuted)

	logPanel, refreshLogs := newApprovalLogPanel(r, 12)

	back := widget.NewButton("← Back to Server Setup", func() { r.showConfig() })
	back.Importance = widget.LowImportance

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(16),
		container.NewHBox(container.New(&fixedSize{w: 56, h: 56}, spinner)),
		vspace(12),
		statusText,
		vspace(6),
		sub,
		vspace(10),
		logPanel,
		vspace(12),
		container.NewHBox(back),
	)
	r.window.SetContent(r.authScreen(form, false))
	events := refreshLogs()
	updateApprovalStatus := func(events []ipc.HistoryEvent) {
		headline, detail := approvalStatusFromEvents(events)
		fyne.Do(func() {
			statusText.Text = headline
			sub.Text = detail
			statusText.Refresh()
			sub.Refresh()
		})
	}
	updateApprovalStatus(events)

	// Poll for approval.
	stop := make(chan struct{})
	r.stopRefresh = stop
	check := func() bool {
		st, err := r.client.Status(r.ctx)
		if err != nil {
			return false
		}
		if !st.HasConfig {
			fyne.Do(func() { r.showConfig() })
			return true
		}
		if st.Approved {
			fyne.Do(func() {
				statusText.Text = "Approved! Continuing…"
				statusText.Refresh()
				r.showLogin()
			})
			return true
		}
		return false
	}
	go func() {
		if check() {
			return
		}
		logTick := time.NewTicker(2 * time.Second)
		approveTick := time.NewTicker(5 * time.Second)
		defer logTick.Stop()
		defer approveTick.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-stop:
				return
			case <-logTick.C:
				events := refreshLogs()
				updateApprovalStatus(events)
			case <-approveTick.C:
				if check() {
					return
				}
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Login (Email / Password)  ->  matches LoginWindow.xaml
// ---------------------------------------------------------------------------

func (r *Router) showLogin() {
	r.stopTicker()
	r.window.Resize(fyne.NewSize(800, 480))

	emailEntry := newPlainEntry()
	emailEntry.SetPlaceHolder("you@example.com")
	passEntry := newPlainPassword()
	passEntry.SetPlaceHolder("Password")

	status := canvasMuted("", colorError)
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	doLogin := func() {
		progress.Show()
		status.Text = ""
		status.Refresh()
		resp, err := r.client.Login(r.ctx, strings.TrimSpace(emailEntry.Text), passEntry.Text)
		progress.Hide()
		if err != nil {
			status.Text = err.Error()
			status.Refresh()
			return
		}
		if !resp.OK {
			status.Text = resp.Message
			status.Refresh()
			return
		}
		passEntry.SetText("")
		emailEntry.SetText("")
		r.showMain()
	}
	passEntry.OnSubmitted = func(string) { doLogin() }

	loginBtn := widget.NewButton("LOG IN", doLogin)
	loginBtn.Importance = widget.HighImportance

	changeSrv := widget.NewButton("Change Server Settings", func() { r.showConfig() })
	changeSrv.Importance = widget.LowImportance

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(24),
		fieldLabel("Email Address"),
		authField(emailEntry),
		vspace(12),
		fieldLabel("Password"),
		authField(passEntry),
		vspace(6),
		canvasMuted("Credentials are not saved on this device.", colorMuted),
		vspace(14),
		tallButton(loginBtn),
		vspace(6),
		container.NewCenter(changeSrv),
		progress,
		container.NewCenter(status),
	)
	r.window.SetContent(r.authScreen(form, true))
}

// ---------------------------------------------------------------------------
// Small shared building blocks
// ---------------------------------------------------------------------------

// newApprovalLogPanel shows recent connection/approval events below the waiting message.
func newApprovalLogPanel(r *Router, maxLines int) (fyne.CanvasObject, func() []ipc.HistoryEvent) {
	logEvents := []ipc.HistoryEvent{}
	logList := widget.NewList(
		func() int { return len(logEvents) },
		func() fyne.CanvasObject {
			t := canvasMuted("", colorMuted)
			t.TextSize = 11
			return t
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			t := o.(*canvas.Text)
			e := logEvents[i]
			t.Text = formatApprovalLogLine(e)
			t.Color = kindColor(e.Kind)
			t.Refresh()
		},
	)

	bg := canvas.NewRectangle(color.NRGBA{R: 0x10, G: 0x17, B: 0x24, A: 0xff})
	bg.CornerRadius = 8
	bg.StrokeColor = colorCardBorder
	bg.StrokeWidth = 1

	head := heading("CONNECTION LOG", 10, colorMuted)
	panel := container.NewBorder(
		container.NewPadded(head),
		nil, nil, nil,
		container.NewStack(bg, container.NewPadded(logList)),
	)

	refresh := func() []ipc.HistoryEvent {
		ev, err := r.client.History(r.ctx, 40)
		if err != nil {
			logEvents = []ipc.HistoryEvent{{
				Time:    time.Now().Format(time.RFC3339),
				Kind:    "api.error",
				Message: "Cannot read activity log: " + err.Error(),
			}}
			logList.Refresh()
			return logEvents
		}
		filtered := filterConnectionEvents(ev, maxLines)
		if len(filtered) == 0 {
			filtered = []ipc.HistoryEvent{{
				Time:    time.Now().Format(time.RFC3339),
				Kind:    "approve.wait",
				Message: "Waiting for connection events…",
			}}
		}
		logEvents = filtered
		logList.Refresh()
		return logEvents
	}

	return container.New(&fixedHeight{h: 132}, panel), refresh
}

func filterConnectionEvents(all []ipc.HistoryEvent, max int) []ipc.HistoryEvent {
	out := make([]ipc.HistoryEvent, 0, max)
	for _, e := range all {
		if !isConnectionLogKind(e.Kind) {
			continue
		}
		out = append(out, e)
		if len(out) >= max {
			break
		}
	}
	return out
}

func isConnectionLogKind(kind string) bool {
	switch {
	case strings.HasPrefix(kind, "approve"):
	case strings.HasPrefix(kind, "api"):
	case strings.HasPrefix(kind, "heartbeat"):
	case strings.HasPrefix(kind, "config"):
	case kind == "runtime.start", kind == "runtime.warn":
	default:
		return false
	}
	return true
}

func formatApprovalLogLine(e ipc.HistoryEvent) string {
	ts := e.Time
	if len(ts) >= 19 {
		ts = ts[11:19]
	}
	msg := e.Message
	if len(msg) > 110 {
		msg = msg[:107] + "…"
	}
	return fmt.Sprintf("%s  [%s] %s", ts, e.Kind, msg)
}

func approvalStatusFromEvents(events []ipc.HistoryEvent) (headline, detail string) {
	headline = "Connecting to server…"
	detail = "Watch CONNECTION LOG below for live steps (dataInfo → approval check)."
	if len(events) == 0 {
		return headline, detail
	}

	// Prefer the most meaningful recent status, not just the newest heartbeat.
	var (
		hasApproveOK   bool
		hasApproveWait bool
		hasAPIError    bool
		hasProgress    bool
		hasDataInfoOK  bool
		latestMsg      = events[0].Message
	)
	for _, e := range events {
		switch {
		case e.Kind == "approve.ok":
			hasApproveOK = true
		case e.Kind == "approve.wait":
			hasApproveWait = true
			latestMsg = e.Message
		case strings.HasPrefix(e.Kind, "api.error"), e.Kind == "api.warn":
			hasAPIError = true
			if !hasApproveWait {
				latestMsg = e.Message
			}
		case e.Kind == "approve.progress":
			hasProgress = true
			if !hasApproveWait && !hasAPIError {
				latestMsg = e.Message
			}
		case e.Kind == "api.ok" && strings.Contains(e.Message, "dataInfo"):
			hasDataInfoOK = true
		}
	}

	switch {
	case hasApproveOK:
		headline = "Device approved"
		detail = "Continuing to login…"
	case hasAPIError:
		headline = "Server connection / API problem"
		detail = latestMsg
	case hasApproveWait:
		headline = "Waiting for administrator approval"
		detail = latestMsg
	case hasDataInfoOK || (hasProgress && strings.Contains(strings.ToLower(latestMsg), "step 2")):
		headline = "Checking approval status"
		detail = latestMsg
	case hasProgress:
		headline = "Registering device with server"
		detail = latestMsg
	default:
		headline = "Working…"
		detail = latestMsg
	}
	return headline, detail
}

// TextWrapOff + ScrollHorizontalOnly keeps long pasted values inside the field
// without the vertical track that TextTruncateClip forces on.
func newPlainEntry() *widget.Entry {
	e := &widget.Entry{
		Wrapping: fyne.TextWrapOff,
		Scroll:   container.ScrollHorizontalOnly,
	}
	e.ExtendBaseWidget(e)
	return e
}

// newPlainPassword masks input like a password field but without the reveal (eye) button.
func newPlainPassword() *widget.Entry {
	e := newPlainEntry()
	e.Password = true
	return e
}

// authField styles text inputs for the dark auth screens (no white frame).
func authField(e fyne.CanvasObject) fyne.CanvasObject {
	if ent, ok := e.(*widget.Entry); ok {
		ent.Wrapping = fyne.TextWrapOff
		ent.Scroll = container.ScrollHorizontalOnly
		ent.ActionItem = nil
	}
	return container.New(&fixedHeight{h: 38}, container.NewMax(e))
}

// tallButton gives a button a fixed comfortable height.
func tallButton(b fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&fixedHeight{h: 46}, b)
}

func fieldLabel(text string) fyne.CanvasObject {
	return heading(strings.ToUpper(text), 11, colorMuted)
}

func canvasMuted(text string, col color.Color) *canvas.Text {
	t := canvas.NewText(text, col)
	t.TextSize = 12
	return t
}

func sectionHeader(text string, icon fyne.Resource) fyne.CanvasObject {
	ic := widget.NewIcon(icon)
	return container.NewHBox(ic, hspace(2), heading(text, 15, colorText))
}

func toggleRow(title, sub string, check *widget.Check) fyne.CanvasObject {
	texts := container.NewVBox(label(title), muted(sub))
	return container.NewBorder(nil, nil, texts, container.NewCenter(check))
}

func infoRow(k, v string) fyne.CanvasObject {
	return container.NewBorder(nil, nil, muted(k), label(v))
}

func divider() fyne.CanvasObject {
	line := canvas.NewRectangle(colorCardBorder)
	line.SetMinSize(fyne.NewSize(1, 1))
	return container.NewPadded(line)
}

func boolPtr(v bool) *bool { return &v }

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	return strings.ToUpper(s[:1]) + s[1:]
}

func fmtCount(n int) string { return fmt.Sprintf("%d", n) }
