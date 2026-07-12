//go:build windows

package ui

import (
	"image/color"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	wmNCLButtonDown = 0x00A1
	htCaption       = 2
	swpNoSize       = 0x0001
	swpNoZOrder     = 0x0004
	vkLButton       = 0x01
)

type winPoint struct{ X, Y int32 }
type winRect struct{ Left, Top, Right, Bottom int32 }

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	procReleaseCap   = user32.NewProc("ReleaseCapture")
	procSendMessage  = user32.NewProc("SendMessageW")
	procPostMessage  = user32.NewProc("PostMessageW")
	procGetCursorPos = user32.NewProc("GetCursorPos")
	procGetWindowRect = user32.NewProc("GetWindowRect")
	procSetWindowPos = user32.NewProc("SetWindowPos")
	procGetAsyncKey  = user32.NewProc("GetAsyncKeyState")
	procFindWindowW  = user32.NewProc("FindWindowW")
)

var _ desktop.Mouseable = (*dragBar)(nil)
var _ desktop.Hoverable = (*dragBar)(nil)

// newChromeWindow creates a borderless, unpadded window like the legacy .NET UI.
func newChromeWindow(a fyne.App, title string) fyne.Window {
	if d, ok := a.Driver().(desktop.Driver); ok {
		w := d.CreateSplashWindow()
		w.SetTitle(title)
		w.SetPadded(false)
		return w
	}
	w := a.NewWindow(title)
	w.SetPadded(false)
	return w
}

func cacheWindowHWND(w fyne.Window, store *atomic.Uintptr, title string) {
	if store.Load() != 0 {
		return
	}
	if nw, ok := w.(driver.NativeWindow); ok {
		nw.RunNative(func(ctx any) {
			if c, ok := ctx.(driver.WindowsWindowContext); ok && c.HWND != 0 {
				store.Store(c.HWND)
			}
		})
	}
	if store.Load() == 0 {
		if h := findWindowByTitle(title); h != 0 {
			store.Store(h)
		}
	}
}

func startHWNDCache(w fyne.Window, store *atomic.Uintptr, title string) {
	go func() {
		for i := 0; i < 40 && store.Load() == 0; i++ {
			cacheWindowHWND(w, store, title)
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func findWindowByTitle(title string) uintptr {
	p, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return 0
	}
	h, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(p)))
	return h
}

func cursorScreenPos() (int32, int32) {
	var pt winPoint
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	return pt.X, pt.Y
}

func windowScreenOrigin(hwnd uintptr) (int32, int32) {
	var r winRect
	_, _, _ = procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r.Left, r.Top
}

func leftButtonDown() bool {
	r, _, _ := procGetAsyncKey.Call(uintptr(vkLButton))
	return r&0x8000 != 0
}

func moveWindow(hwnd uintptr, x, y int32) {
	_, _, _ = procSetWindowPos.Call(
		hwnd, 0,
		uintptr(x), uintptr(y),
		0, 0,
		uintptr(swpNoSize|swpNoZOrder),
	)
}

// startWindowDrag moves a borderless window while the left mouse button is held.
func startWindowDrag(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	cx, cy := cursorScreenPos()
	wx, wy := windowScreenOrigin(hwnd)
	offX, offY := cx-wx, cy-wy

	// Win32 caption drag (works on some GLFW builds).
	_, _, _ = procReleaseCap.Call()
	lp := uintptr(uint32(uint16(cx)) | uint32(uint16(cy))<<16)
	_, _, _ = procPostMessage.Call(hwnd, uintptr(wmNCLButtonDown), uintptr(htCaption), lp)

	go func() {
		for leftButtonDown() {
			x, y := cursorScreenPos()
			moveWindow(hwnd, x-offX, y-offY)
			time.Sleep(8 * time.Millisecond)
		}
	}()
}

// dragBar is the draggable region in the top chrome (center of the title bar).
type dragBar struct {
	widget.BaseWidget
	hwnd func() uintptr
}

func newDragBar(hwnd func() uintptr) *dragBar {
	d := &dragBar{hwnd: hwnd}
	d.ExtendBaseWidget(d)
	return d
}

func (d *dragBar) MinSize() fyne.Size { return fyne.NewSize(80, 40) }

func (d *dragBar) MouseDown(e *desktop.MouseEvent) {
	if e.Button != desktop.MouseButtonPrimary {
		return
	}
	startWindowDrag(d.hwnd())
}

func (d *dragBar) MouseUp(*desktop.MouseEvent)   {}
func (d *dragBar) MouseIn(*desktop.MouseEvent)   {}
func (d *dragBar) MouseOut()                     {}
func (d *dragBar) MouseMoved(*desktop.MouseEvent) {}

func (d *dragBar) CreateRenderer() fyne.WidgetRenderer {
	// Must be hit-testable; fully transparent rects ignore clicks in Fyne.
	r := canvas.NewRectangle(color.NRGBA{R: 0, G: 0, B: 0, A: 2})
	grip := canvas.NewText("⋯", color.NRGBA{R: 0x94, G: 0xa3, B: 0xb8, A: 0x90})
	grip.TextSize = 18
	grip.Alignment = fyne.TextAlignCenter
	return widget.NewSimpleRenderer(container.NewStack(r, container.NewCenter(grip)))
}

// draggableTopBar: [left controls] [drag grip] [right controls] on a dark bar.
func draggableTopBar(bg fyne.CanvasObject, height float32, left, right fyne.CanvasObject, drag fyne.CanvasObject) fyne.CanvasObject {
	row := container.NewBorder(nil, nil, left, right, drag)
	return container.New(&fixedHeight{h: height}, container.NewStack(bg, row))
}

// chromeMenuButton returns a compact menu button for the title bar.
func chromeMenuButton(onTap func()) fyne.CanvasObject {
	b := widget.NewButtonWithIcon("", theme.MenuIcon(), onTap)
	b.Importance = widget.LowImportance
	return b
}

// chromeCloseButton returns a compact close button for the title bar.
func chromeCloseButton(onTap func()) fyne.CanvasObject {
	b := widget.NewButtonWithIcon("", theme.CancelIcon(), onTap)
	b.Importance = widget.LowImportance
	return b
}
