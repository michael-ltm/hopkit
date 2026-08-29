package ui

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// SanitizeTerminalText removes ANSI escape sequences and terminal control
// characters from config-backed values before rendering them. New metadata is
// validated on write, but hand-edited and legacy configs are still untrusted.
func SanitizeTerminalText(value string) string {
	value = ansi.Strip(value)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			switch r {
			case '\t', '\n', '\r':
				return ' '
			default:
				return -1
			}
		}
		return r
	}, value)
}

// TruncateWidth returns value constrained to at most max terminal cells. It
// uses display width rather than rune count, so CJK server descriptions do not
// unexpectedly wrap a supposedly single-line interactive option.
func TruncateWidth(value string, max int) string {
	if max <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= max {
		return value
	}
	if max == 1 {
		return "…"
	}
	var b strings.Builder
	for _, r := range value {
		candidate := b.String() + string(r)
		if lipgloss.Width(candidate)+1 > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "…"
}

// PadRightWidth pads value to exactly width terminal cells after truncating.
func PadRightWidth(value string, width int) string {
	value = TruncateWidth(value, width)
	if pad := width - lipgloss.Width(value); pad > 0 {
		value += strings.Repeat(" ", pad)
	}
	return value
}
