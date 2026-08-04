//go:build windows

package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

type dangerButton struct {
	widget.BaseWidget
	Text    string
	OnTap   func()
	rect    *canvas.Rectangle
	txt     *canvas.Text
	hovered bool
}

func newDangerButton(text string, onTap func()) *dangerButton {
	b := &dangerButton{
		Text:  text,
		OnTap: onTap,
	}
	b.rect = canvas.NewRectangle(colorError)
	b.rect.CornerRadius = 8
	b.txt = canvas.NewText(text, colorOnAccent)
	b.txt.TextStyle = fyne.TextStyle{Bold: true}
	b.txt.TextSize = 14
	b.txt.Alignment = fyne.TextAlignCenter
	b.ExtendBaseWidget(b)
	return b
}

func (b *dangerButton) CreateRenderer() fyne.WidgetRenderer {
	c := container.NewStack(b.rect, container.NewCenter(b.txt))
	return widget.NewSimpleRenderer(c)
}

func (b *dangerButton) Tapped(*fyne.PointEvent) {
	if b.OnTap != nil {
		b.OnTap()
	}
}

func (b *dangerButton) MouseIn(*desktop.MouseEvent) {
	b.hovered = true
	b.rect.FillColor = color.NRGBA{R: 0xdc, G: 0x26, B: 0x26, A: 0xff}
	b.rect.Refresh()
}

func (b *dangerButton) MouseOut() {
	b.hovered = false
	b.rect.FillColor = colorError
	b.rect.Refresh()
}

func (b *dangerButton) MouseMoved(*desktop.MouseEvent) {}

// card wraps content in a rounded, bordered surface panel.
func card(content fyne.CanvasObject) *fyne.Container {
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = 14
	bg.StrokeColor = colorCardBorder
	bg.StrokeWidth = 1
	return container.NewStack(bg, container.NewPadded(content))
}

// accentCard is a card with a colored, translucent background used to draw the
// eye to the most important status on screen.
func accentCard(content fyne.CanvasObject, fill, stroke color.Color) *fyne.Container {
	bg := canvas.NewRectangle(fill)
	bg.CornerRadius = 16
	bg.StrokeColor = stroke
	bg.StrokeWidth = 1
	return container.NewStack(bg, container.NewPadded(content))
}

// brandLogo renders the square "S" brand mark at the requested size.
func brandLogo(size float32) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorPrimary)
	bg.CornerRadius = size * 0.28
	bg.SetMinSize(fyne.NewSize(size, size))

	letter := canvas.NewText("S", colorOnAccent)
	letter.TextStyle = fyne.TextStyle{Bold: true}
	letter.TextSize = size * 0.56
	letter.Alignment = fyne.TextAlignCenter

	return container.NewStack(bg, container.NewCenter(letter))
}

// heading is a bold canvas text at the given size/color.
func heading(text string, size float32, col color.Color) *canvas.Text {
	t := canvas.NewText(text, col)
	t.TextStyle = fyne.TextStyle{Bold: true}
	t.TextSize = size
	return t
}

// muted is small, dimmed caption text.
func muted(text string) *canvas.Text {
	t := canvas.NewText(text, colorMuted)
	t.TextSize = 12
	return t
}

// label is body text in the primary foreground color.
func label(text string) *canvas.Text {
	t := canvas.NewText(text, colorText)
	t.TextSize = 14
	return t
}

// sizedCircle is a circle with a fixed minimum size, used as a status dot.
type sizedCircle struct {
	canvas.Circle
	sz float32
}

func statusDot(col color.Color, sz float32) *sizedCircle {
	c := &sizedCircle{sz: sz}
	c.FillColor = col
	return c
}

func (c *sizedCircle) MinSize() fyne.Size { return fyne.NewSize(c.sz, c.sz) }

// vspace returns a fixed vertical spacer.
func vspace(h float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(1, h))
	return r
}

// hspace returns a fixed horizontal spacer.
func hspace(w float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(w, 1))
	return r
}

// fixedWidth constrains its child to an exact width while letting height grow
// with content — perfect for centered auth cards.
type fixedWidth struct{ w float32 }

func (f fixedWidth) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var h float32
	for _, o := range objs {
		if m := o.MinSize(); m.Height > h {
			h = m.Height
		}
	}
	return fyne.NewSize(f.w, h)
}

func (f fixedWidth) Layout(objs []fyne.CanvasObject, s fyne.Size) {
	for _, o := range objs {
		o.Resize(s)
		o.Move(fyne.NewPos(0, 0))
	}
}

// flexWidth lets content fill the parent width while reporting MinWidth=0 so
// long labels cannot stretch the main window (Fyne grows the window to MinSize).
type flexWidth struct{}

func (flexWidth) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var h float32
	for _, o := range objs {
		if m := o.MinSize(); m.Height > h {
			h = m.Height
		}
	}
	return fyne.NewSize(0, h)
}

func (flexWidth) Layout(objs []fyne.CanvasObject, s fyne.Size) {
	for _, o := range objs {
		o.Resize(s)
		o.Move(fyne.NewPos(0, 0))
	}
}

// constrained centers content at a fixed maximum width.
func constrained(w float32, content fyne.CanvasObject) fyne.CanvasObject {
	return container.NewCenter(container.New(&fixedWidth{w: w}, content))
}

// fixedHeight forces its children to an exact height (width flexible).
type fixedHeight struct{ h float32 }

func (f *fixedHeight) MinSize(objs []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(0, f.h)
}

func (f *fixedHeight) Layout(objs []fyne.CanvasObject, s fyne.Size) {
	for _, o := range objs {
		o.Resize(s)
		o.Move(fyne.NewPos(0, 0))
	}
}

// rightCoverLayout scales a single image like CSS object-fit:cover, anchored to the right.
// Matches legacy ConfigWindow bg-login.png (UniformToFill + HorizontalAlignment=Right).
type rightCoverLayout struct{}

func (rightCoverLayout) MinSize(_ []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(1, 1)
}

func (rightCoverLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objs {
		im, ok := o.(*canvas.Image)
		if !ok {
			o.Resize(size)
			o.Move(fyne.NewPos(0, 0))
			continue
		}
		aspect := im.Aspect()
		if aspect <= 0 {
			im.FillMode = canvas.ImageFillStretch
			im.Resize(size)
			im.Move(fyne.NewPos(0, 0))
			continue
		}
		var w, h float32
		containerAspect := size.Width / size.Height
		if aspect > containerAspect {
			h = size.Height
			w = h * aspect
		} else {
			w = size.Width
			h = w / aspect
		}
		im.FillMode = canvas.ImageFillStretch
		im.Resize(fyne.NewSize(w, h))
		im.Move(fyne.NewPos(size.Width-w, (size.Height-h)/2))
	}
}

// fixedSize forces its children to an exact width and height.
type fixedSize struct{ w, h float32 }

func (f *fixedSize) MinSize(objs []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(f.w, f.h)
}

func (f *fixedSize) Layout(objs []fyne.CanvasObject, s fyne.Size) {
	for _, o := range objs {
		o.Resize(s)
		o.Move(fyne.NewPos(0, 0))
	}
}

// pill is a small rounded, colored chip with a caption inside.
func pill(text string, fg, bg color.Color) fyne.CanvasObject {
	r := canvas.NewRectangle(bg)
	r.CornerRadius = 11
	t := heading(text, 11, fg)
	return container.NewStack(r, container.NewPadded(container.NewHBox(t)))
}

// statCard shows a compact metric: a small uppercase caption over a large
// bold value. The returned value/sub texts can be mutated then Refresh()'d.
type statCard struct {
	root  fyne.CanvasObject
	value *canvas.Text
	sub   *canvas.Text
	acc   *canvas.Rectangle
}

func newStatCard(title string) *statCard {
	acc := canvas.NewRectangle(colorPrimary)
	acc.CornerRadius = 2
	acc.SetMinSize(fyne.NewSize(3, 20))

	capText := heading(title, 11, colorMuted)
	head := container.NewHBox(acc, capText)

	val := heading("—", 22, colorText)
	sub := muted("")

	body := container.NewVBox(head, vspace(2), val, sub)
	return &statCard{root: card(body), value: val, sub: sub, acc: acc}
}

func (s *statCard) set(value, sub string, valueColor, accent color.Color) {
	s.value.Text = value
	s.value.Color = valueColor
	s.sub.Text = sub
	s.acc.FillColor = accent
	s.value.Refresh()
	s.sub.Refresh()
	s.acc.Refresh()
}
