// Package ui holds rendering primitives — icons, color styles, and table
// formatting — used by CLI commands. It must not import internal/ssh or
// any package that performs I/O.
package ui

import (
	"os"
	"runtime"

	"github.com/mattn/go-isatty"
)

// IconSet bundles every glyph used in lists and details.
type IconSet struct {
	Online       string
	Offline      string
	Unknown      string
	None         string
	AuthKey      string
	AuthPassword string
	AuthAgent    string
}

// UnicodeIcons returns the rich glyph set used on modern terminals.
func UnicodeIcons() IconSet {
	return IconSet{
		Online: "✓", Offline: "✗", Unknown: "◌", None: "—",
		AuthKey: "🔒", AuthPassword: "🔑", AuthAgent: "🤝",
	}
}

// ASCIIIcons returns a plain set safe on every terminal.
func ASCIIIcons() IconSet {
	return IconSet{
		Online: "[OK]", Offline: "[X]", Unknown: "[?]", None: "[--]",
		AuthKey: "[K]", AuthPassword: "[P]", AuthAgent: "[A]",
	}
}

// ResolveIcons honors an explicit user choice; otherwise picks unicode on
// modern terminals and falls back to ascii on Windows non-Terminal hosts.
func ResolveIcons(pref string) IconSet {
	switch pref {
	case "unicode":
		return UnicodeIcons()
	case "ascii":
		return ASCIIIcons()
	}
	// auto-detect
	if runtime.GOOS == "windows" {
		// Windows Terminal sets WT_SESSION; legacy cmd.exe does not.
		if os.Getenv("WT_SESSION") == "" {
			return ASCIIIcons()
		}
	}
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return ASCIIIcons()
	}
	return UnicodeIcons()
}
