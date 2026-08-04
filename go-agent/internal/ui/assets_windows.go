//go:build windows

package ui

import (
	_ "embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
)

// Embedded brand assets, migrated verbatim from the legacy .NET UI so the Go
// agent keeps the exact same look. Bundled into the binary — no external files.

//go:embed assets/bg_login.png
var assetBgLogin []byte

//go:embed assets/logo_full.png
var assetLogoFull []byte

//go:embed assets/logo_mark.png
var assetLogoMark []byte

//go:embed assets/logo_about.png
var assetLogoAbout []byte

//go:embed assets/icon_main.png
var assetIconMain []byte

//go:embed assets/icon_status.png
var assetIconStatus []byte

//go:embed assets/icon_setting.png
var assetIconSetting []byte

//go:embed assets/icon_info.png
var assetIconInfo []byte

//go:embed assets/icon_scan.png
var assetIconScan []byte

//go:embed assets/icon_log.png
var assetIconLog []byte

//go:embed assets/icon_yara.png
var assetIconYara []byte

//go:embed assets/icon_hash.png
var assetIconHash []byte

//go:embed assets/icon_batch.png
var assetIconBatch []byte

//go:embed assets/icon_quick_scan.png
var assetIconQuickScan []byte

//go:embed assets/icon_conn.png
var assetIconConn []byte

//go:embed assets/icon_realtime.png
var assetIconRealtime []byte

//go:embed assets/icon_usb.png
var assetIconUSB []byte

//go:embed assets/icon_ext.png
var assetIconExt []byte

var (
	resBgLogin   = fyne.NewStaticResource("bg_login.png", assetBgLogin)
	resLogoFull  = fyne.NewStaticResource("logo_full.png", assetLogoFull)
	resLogoMark  = fyne.NewStaticResource("logo_mark.png", assetLogoMark)
	resLogoAbout = fyne.NewStaticResource("logo_about.png", assetLogoAbout)
	resIconMain  = fyne.NewStaticResource("icon_main.png", assetIconMain)
	resIconStat  = fyne.NewStaticResource("icon_status.png", assetIconStatus)
	resIconSet   = fyne.NewStaticResource("icon_setting.png", assetIconSetting)
	resIconInfo  = fyne.NewStaticResource("icon_info.png", assetIconInfo)
	resIconScan  = fyne.NewStaticResource("icon_scan.png", assetIconScan)
	resIconLog   = fyne.NewStaticResource("icon_log.png", assetIconLog)
	resIconYara  = fyne.NewStaticResource("icon_yara.png", assetIconYara)
	resIconHash  = fyne.NewStaticResource("icon_hash.png", assetIconHash)
	resIconBatch = fyne.NewStaticResource("icon_batch.png", assetIconBatch)
	resIconQuick = fyne.NewStaticResource("icon_quick_scan.png", assetIconQuickScan)
	resIconConn  = fyne.NewStaticResource("icon_conn.png", assetIconConn)
	resIconRT    = fyne.NewStaticResource("icon_realtime.png", assetIconRealtime)
	resIconUSB   = fyne.NewStaticResource("icon_usb.png", assetIconUSB)
	resIconExt   = fyne.NewStaticResource("icon_ext.png", assetIconExt)
)

// img returns a contained (aspect-fit) image sized to the given box.
func img(res fyne.Resource, w, h float32) *canvas.Image {
	im := canvas.NewImageFromResource(res)
	im.FillMode = canvas.ImageFillContain
	im.SetMinSize(fyne.NewSize(w, h))
	return im
}

// authBackground fills the entire auth window with the branded backdrop image.
// Matches legacy WPF: Stretch=UniformToFill, HorizontalAlignment=Right, Opacity=0.8.
func authBackground() fyne.CanvasObject {
	im := canvas.NewImageFromResource(resBgLogin)
	im.Translucency = 0.2
	return container.New(&rightCoverLayout{}, im)
}
