//go:build windows

package ui

import (
	"context"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/ipc"
)

// RunConfirmExit shows login credentials before closing the tray UI process.
func RunConfirmExit(ctx context.Context, client *ipc.Client) error {
	prepareSoftwareGL()
	a := app.NewWithID("com.sosecure.insite-agent.confirm-exit")
	a.Settings().SetTheme(insiteTheme{})
	a.SetIcon(resIconMain)

	w := newChromeWindow(a, appTitle+" — Confirm Exit")
	w.SetIcon(resIconMain)
	w.Resize(fyne.NewSize(800, 480))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	r := &Router{app: a, window: w, client: client, ctx: ctx}
	startHWNDCache(w, &r.hwnd, appTitle+" — Confirm Exit")

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
		loginCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		resp, err := client.Login(loginCtx, email, pass)
		cancel()
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
		if err := requestUIQuit(); err != nil {
			status.Text = "Authorized, but could not signal UI to close: " + err.Error()
			status.Color = colorError
			status.Refresh()
			return
		}
		status.Text = "Closing…"
		status.Color = colorMuted
		status.Refresh()
		go func() {
			time.Sleep(200 * time.Millisecond)
			w.Close()
			a.Quit()
		}()
	}
	passEntry.OnSubmitted = func(string) { doConfirm() }

	confirmBtn := widget.NewButton("CONFIRM EXIT", doConfirm)
	confirmBtn.Importance = widget.DangerImportance
	cancelBtn := widget.NewButton("Cancel", func() {
		w.Close()
		a.Quit()
	})

	purpose := widget.NewLabel("Enter your account email and password to close the UI. The background service will keep protecting this device.")
	purpose.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(16),
		heading("Confirm Exit", 18, colorText),
		vspace(8),
		purpose,
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
	w.SetContent(r.authScreen(form, false))
	w.Canvas().Focus(emailEntry)
	w.ShowAndRun()
	return nil
}
