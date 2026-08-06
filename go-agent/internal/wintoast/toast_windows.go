//go:build windows

package wintoast

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultAppID = "SOSECURE Threat inSight"

var (
	mu       sync.Mutex
	lastPush time.Time
	minGap   = 1500 * time.Millisecond
)

// Notify shows a Windows Action Center toast near the system tray.
// Safe to call from any goroutine; failures are ignored by callers.
func Notify(title, message string) error {
	title = strings.TrimSpace(title)
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	if title == "" {
		title = defaultAppID
	}

	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	if now.Sub(lastPush) < minGap {
		return nil
	}
	lastPush = now

	xml := buildToastXML(defaultAppID, title, message)
	tmp, err := os.CreateTemp("", "insite-toast-*.ps1")
	if err != nil {
		return err
	}
	path := tmp.Name()
	defer os.Remove(path)

	// UTF-8 BOM helps PowerShell parse non-ASCII paths/messages.
	if _, err := tmp.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		tmp.Close()
		return err
	}
	script := "$ErrorActionPreference = 'Stop'\n" +
		"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\n" +
		"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null\n" +
		"$xml = New-Object Windows.Data.Xml.Dom.XmlDocument\n" +
		"$xml.LoadXml(@'\n" + xml + "\n'@)\n" +
		"$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)\n" +
		"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('" + escapePS(defaultAppID) + "').Show($toast)\n"
	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	cmd := exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", filepath.Clean(path),
	)
	cmd.SysProcAttr = hiddenPowerShellAttr()
	return cmd.Run()
}

func buildToastXML(appID, title, message string) string {
	return `<toast activationType="protocol">` +
		`<visual><binding template="ToastGeneric">` +
		`<text>` + xmlEscape(title) + `</text>` +
		`<text>` + xmlEscape(message) + `</text>` +
		`</binding></visual>` +
		`</toast>`
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		`&`, "&amp;",
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&quot;",
		`'`, "&apos;",
	)
	return r.Replace(s)
}

func escapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
