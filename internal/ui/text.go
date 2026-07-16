package ui

import (
	"strings"
	"unicode"

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
