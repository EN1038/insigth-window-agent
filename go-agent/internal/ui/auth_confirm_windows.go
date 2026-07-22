//go:build windows

package ui

import (
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver"
	"fyne.io/fyne/v2/widget"
)

const (
	swRestore    = 9
	swShow       = 5
	swShowNormal = 1
)

var (
	procShowWindow               = user32.NewProc("ShowWindow")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop         = user32.NewProc("BringWindowToTop")
	procAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
)

// runOnUI runs fn on the Fyne/GLFW main thread.
// fn must NOT call Window.Show/Hide/Resize/RequestFocus (those re-enter runOnMain and deadlock).
func (r *Router) runOnUI(fn func()) {
	if r.window == nil {
		fn()
		return
	}
	if nw, ok := r.window.(driver.NativeWindow); ok {
		nw.RunNative(func(any) { fn() })
		return
	}
	fn()
}

// scheduleUI runs fn on the UI thread without blocking the tray callback.
func (r *Router) scheduleUI(fn func()) {
	go func() { r.runOnUI(fn) }()
}

func (r *Router) ensureHWND() uintptr {
	hwnd := r.hwnd.Load()
	if hwnd != 0 {
		return hwnd
	}
	if r.window != nil {
		cacheWindowHWND(r.window, &r.hwnd, appTitle)
		hwnd = r.hwnd.Load()
	}
	return hwnd
}

// forceShowNative restores the window via Win32 (safe from any thread, including UI main).
func (r *Router) forceShowNative() {
	hwnd := r.ensureHWND()
	if hwnd == 0 {
		hwnd = findWindowByTitle(appTitle)
		if hwnd != 0 {
			r.hwnd.Store(hwnd)
		}
	}
	if hwnd == 0 {
		return
	}
	_, _, _ = procAllowSetForegroundWindow.Call(^uintptr(0)) // ASFW_ANY
	_, _, _ = procShowWindow.Call(hwnd, uintptr(swRestore))
	_, _, _ = procShowWindow.Call(hwnd, uintptr(swShowNormal))
	_, _, _ = procShowWindow.Call(hwnd, uintptr(swShow))
	_, _, _ = procBringWindowToTop.Call(hwnd)
	_, _, _ = procSetForegroundWindow.Call(hwnd)
}

// bringToFrontFromTray shows a hidden window. Call from tray (non-UI) thread only:
// Window.Show schedules work onto the UI thread; calling it from RunNative deadlocks.
func (r *Router) bringToFrontFromTray() {
	if r.window == nil {
		return
	}
	r.window.Show()
	r.window.RequestFocus()
	// Give doShowAgain a moment to run on the UI thread, then force Z-order.
	time.Sleep(80 * time.Millisecond)
	r.forceShowNative()
}

// showCredentialConfirm asks for email/password (same as login) before a sensitive action.
// onOK runs only after successful Login API validation.
// Must be called from the Fyne main thread; must not call Show/Resize/RequestFocus.
func (r *Router) showCredentialConfirm(title, purpose string, onOK func()) {
	r.stopTicker()

	emailEntry := newPlainEntry()
	emailEntry.SetPlaceHolder("you@example.com")
	passEntry := newPlainPassword()
	passEntry.SetPlaceHolder("Password")
	status := canvasMuted("", colorError)

	doConfirm := func() {
		email := strings.TrimSpace(emailEntry.Text)
		pass := passEntry.Text
		if email == "" || pass == "" {
			status.Text = "Email and password are required"
			status.Refresh()
			return
		}
		status.Text = "Verifying…"
		status.Color = colorMuted
		status.Refresh()
		resp, err := r.client.Login(r.ctx, email, pass)
		if err != nil {
			status.Text = err.Error()
			status.Color = colorError
			status.Refresh()
			return
		}
		if !resp.OK {
			msg := resp.Message
			if msg == "" {
				msg = "Login failed"
			}
			status.Text = msg
			status.Color = colorError
			status.Refresh()
			return
		}
		passEntry.SetText("")
		onOK()
	}
	passEntry.OnSubmitted = func(string) { doConfirm() }

	confirmBtn := widget.NewButton("CONFIRM", doConfirm)
	confirmBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButton("Cancel", func() {
		r.showFlow()
	})
	cancelBtn.Importance = widget.LowImportance

	purposeLbl := widget.NewLabel(purpose)
	purposeLbl.Wrapping = fyne.TextWrapWord
	purposeLbl.Alignment = fyne.TextAlignCenter

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(16),
		heading(title, 18, colorText),
		vspace(8),
		purposeLbl,
		vspace(16),
		fieldLabel("Email / ID"),
		authField(emailEntry),
		vspace(12),
		fieldLabel("Password"),
		authField(passEntry),
		vspace(16),
		tallButton(confirmBtn),
		vspace(8),
		tallButton(cancelBtn),
		vspace(8),
		container.NewCenter(status),
	)
	r.window.SetContent(r.authScreen(form, false))
	r.window.Canvas().Focus(emailEntry)
}
