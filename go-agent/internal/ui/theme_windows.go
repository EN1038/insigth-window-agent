//go:build windows

package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Brand palette for the SOSECURE Threat inSight agent. A calm, deep "control
// room" dark surface paired with a confident teal accent that reads as
// "secure / protected".
// Palette migrated verbatim from the legacy .NET App.xaml so the Go UI matches.
var (
	colorPrimary    = color.NRGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0xff} // #3B82F6 accent blue
	colorPrimaryDim = color.NRGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0x22} // translucent blue wash
	colorAccentCyan = color.NRGBA{R: 0x06, G: 0xb6, B: 0xd4, A: 0xff} // #06B6D4 "SOSECURE"
	colorSuccess    = color.NRGBA{R: 0x10, G: 0xb9, B: 0x81, A: 0xff} // #10B981
	colorStatusGrn  = color.NRGBA{R: 0x4a, G: 0xde, B: 0x80, A: 0xff} // #4ADE80 online dot
	colorError      = color.NRGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff} // #EF4444
	colorWarning    = color.NRGBA{R: 0xf5, G: 0x9e, B: 0x0b, A: 0xff} // #F59E0B

	colorBg         = color.NRGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 0xff} // #0F172A DeepNavy
	colorCard       = color.NRGBA{R: 0x1e, G: 0x29, B: 0x3b, A: 0xff} // #1E293B SlateGray
	colorCardBorder = color.NRGBA{R: 0x33, G: 0x41, B: 0x55, A: 0xff} // #334155
	colorSidebar    = color.NRGBA{R: 0x1e, G: 0x3a, B: 0x5f, A: 0xff} // #1E3A5F sidebar
	colorText       = color.NRGBA{R: 0xe2, G: 0xe8, B: 0xf0, A: 0xff} // #E2E8F0
	colorMuted      = color.NRGBA{R: 0x94, G: 0xa3, B: 0xb8, A: 0xff} // #94A3B8
	colorOnAccent   = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff} // white on blue

	// Scan button gradient endpoints + timeline accent.
	colorScanGradA = color.NRGBA{R: 0x25, G: 0x63, B: 0xeb, A: 0xff} // #2563EB
	colorScanGradB = color.NRGBA{R: 0x08, G: 0x91, B: 0xb2, A: 0xff} // #0891B2
	colorTimeline  = color.NRGBA{R: 0x21, G: 0x4d, B: 0x91, A: 0xff} // #214D91
)

// insiteTheme is a fully custom Fyne theme so every screen picks up the brand
// look without touching individual widgets.
type insiteTheme struct{}

var _ fyne.Theme = insiteTheme{}

func (insiteTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorBg
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnSuccess:
		return colorOnAccent
	case theme.ColorNamePrimary, theme.ColorNameHyperlink, theme.ColorNameFocus:
		return colorPrimary
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x1b, G: 0x23, B: 0x33, A: 0xff}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0x15, G: 0x1c, B: 0x29, A: 0xff}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x10, G: 0x17, B: 0x24, A: 0xff}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x2a, G: 0x35, B: 0x49, A: 0xff}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x20, G: 0x2b, B: 0x3d, A: 0xff}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x2a, G: 0x37, B: 0x4d, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return colorMuted
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x52, G: 0x5c, B: 0x70, A: 0xff}
	case theme.ColorNameSeparator:
		return colorCardBorder
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return colorCard
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 0x10, G: 0x16, B: 0x22, A: 0xff}
	case theme.ColorNameSuccess:
		return colorSuccess
	case theme.ColorNameError, theme.ColorNameForegroundOnError:
		return colorError
	case theme.ColorNameWarning:
		return colorWarning
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x2d, G: 0xd4, B: 0xbf, A: 0x40}
	case theme.ColorNameScrollBar:
		return color.NRGBA{A: 0x00}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x73}
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (insiteTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (insiteTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (insiteTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 26
	case theme.SizeNameSubHeadingText:
		return 18
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameInputRadius:
		return 9
	case theme.SizeNameSelectionRadius:
		return 8
	case theme.SizeNameScrollBar, theme.SizeNameScrollBarSmall:
		return 0
	case theme.SizeNameSeparatorThickness:
		return 1
	}
	return theme.DefaultTheme().Size(name)
}
