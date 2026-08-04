//go:build windows

package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/sosecure/insite-agent/internal/ipc"
)

// RunConfirmStop shows a credential form used when someone tries to stop protection.
// onAuthorizedStop is called after successful login (e.g. stop main + watchdog services).
func RunConfirmStop(ctx context.Context, client *ipc.Client, onAuthorizedStop func() error) error {
	prepareSoftwareGL()
	a := app.NewWithID("com.sosecure.insite-agent.confirm-stop")
	a.Settings().SetTheme(insiteTheme{})
	a.SetIcon(resIconMain)

	w := newChromeWindow(a, appTitle+" — Confirm Stop")
	w.SetIcon(resIconMain)
	w.Resize(fyne.NewSize(800, 480))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	r := &Router{app: a, window: w, client: client, ctx: ctx}
	startHWNDCache(w, &r.hwnd, appTitle+" — Confirm Stop")

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
		status.Text = "Stopping protection…"
		status.Color = colorMuted
		status.Refresh()
		if onAuthorizedStop != nil {
			if err := onAuthorizedStop(); err != nil {
				status.Text = fmt.Sprintf("Authorized, but stop failed: %v", err)
				status.Color = colorError
				status.Refresh()
				return
			}
		}
		w.Close()
		a.Quit()
	}
	passEntry.OnSubmitted = func(string) { doConfirm() }

	confirmBtn := newDangerButton("CONFIRM STOP PROTECTION", doConfirm)
	cancelBtn := widget.NewButton("Cancel (keep protection running)", func() {
		w.Close()
		a.Quit()
	})

	purpose := widget.NewLabel("Protection was stopped or a stop was requested. Enter your account email and password to authorize stopping the agent services. Cancel keeps protection running (watchdog will restart the agent).")
	purpose.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(
		img(resLogoFull, 220, 66),
		vspace(16),
		heading("Confirm Stop Protection", 18, colorText),
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
	w.ShowAndRun()
	return nil
}
