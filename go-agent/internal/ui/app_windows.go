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
			dialog.ShowInformation(
				"Background service not running",
				"Running in standalone mode inside this window.\n"+
					"Real-time protection runs only while this window stays open.\n\n"+
					"Start the \""+appTitle+"\" Windows service for always-on protection.",
				w,
			)
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
	// System tray menu keeps the app alive even if window is hidden.
	if desk, ok := r.app.(desktop.App); ok {
		desk.SetSystemTrayMenu(fyne.NewMenu("",
			fyne.NewMenuItem("Open", func() {
				r.window.Show()
				r.window.RequestFocus()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Exit", func() {
				msg := "Close the UI?\n\nThe background service will keep protecting this device."
				if r.embedded {
					msg = "Close the UI?\n\nStandalone mode is running inside this window. Closing it will stop protection on this device."
				}
				dialog.ShowConfirm("Exit", msg, func(ok bool) {
					if !ok {
						return
					}
					// Disable intercept so Close actually exits.
					r.window.SetCloseIntercept(nil)
					r.window.Close()
					r.app.Quit()
				}, r.window)
			}),
		))
		desk.SetSystemTrayIcon(resIconMain)
	}

	// Close button (✕) should minimize to tray instead of exiting.
	r.window.SetCloseIntercept(func() {
		r.window.Hide()
	})
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
	r.window.Resize(fyne.NewSize(800, 480))
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

	closeBtn := chromeCloseButton(func() { r.window.Close() })
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
		if ok {
			dot.FillColor = colorStatusGrn
			lbl.Text = "Online"
		} else {
			dot.FillColor = colorError
			lbl.Text = "Offline"
		}
		dot.Refresh()
		lbl.Refresh()
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
	keyEntry.SetPlaceHolder("Site key (token) — re-enter to change")

	if cfg, err := r.client.GetConfig(r.ctx); err == nil {
		ipEntry.SetText(cfg.SiteIP)
		codeEntry.SetText(cfg.SiteID)
		// Site key is never loaded from disk into the UI.
	}

	status := canvasMuted("Enter your server details to continue", colorMuted)

	saveBtn := widget.NewButton("SAVE & CONNECT", func() {
		resp, err := r.client.SaveConfig(r.ctx, ipc.SaveConfigRequest{
			SiteIP:  strings.TrimSpace(ipEntry.Text),
			SiteID:  strings.TrimSpace(codeEntry.Text),
			SiteKey: strings.TrimSpace(keyEntry.Text),
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

	logPanel, refreshLogs := newApprovalLogPanel(r, 8)

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
	refreshLogs()
	updateApprovalStatus := func(events []ipc.HistoryEvent) {
		headline, detail := approvalStatusFromEvents(events)
		statusText.Text = headline
		sub.Text = detail
		statusText.Refresh()
		sub.Refresh()
	}

	// Poll for approval.
	stop := make(chan struct{})
	r.stopRefresh = stop
	check := func() bool {
		st, err := r.client.Status(r.ctx)
		if err != nil {
			return false
		}
		if !st.HasConfig {
			r.showConfig()
			return true
		}
		if st.Approved {
			statusText.Text = "Approved! Continuing…"
			statusText.Refresh()
			r.showLogin()
			return true
		}
		return false
	}
	go func() {
		if check() {
			return
		}
		logTick := time.NewTicker(4 * time.Second)
		approveTick := time.NewTicker(10 * time.Second)
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
	if len(msg) > 96 {
		msg = msg[:93] + "…"
	}
	return fmt.Sprintf("%s  %s", ts, msg)
}

func approvalStatusFromEvents(events []ipc.HistoryEvent) (headline, detail string) {
	headline = "Registering device info to server..."
	detail = "Waiting for administrator approval to activate this device."
	if len(events) == 0 {
		return headline, detail
	}
	latest := events[0]
	switch {
	case latest.Kind == "approve.ok":
		headline = "Device approved"
		detail = "Continuing to login…"
	case strings.Contains(latest.Message, "dataInfo registration"):
		headline = "Registering device info to server..."
		detail = "Sending machine details to the server. Check connection log below."
	case latest.Kind == "approve.wait":
		headline = "Waiting for administrator approval"
		detail = "Device registered. An admin must approve this machine on the server."
	case strings.HasPrefix(latest.Kind, "api.error"):
		headline = "Connection problem"
		detail = "Could not reach the server. Verify Server Settings or network, then watch the log below."
	case latest.Kind == "heartbeat.ok", latest.Kind == "api.ok":
		headline = "Connected to server"
		detail = "Server is reachable. Waiting for registration or approval to complete."
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
