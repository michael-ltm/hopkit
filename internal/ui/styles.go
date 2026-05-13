package ui

import "github.com/charmbracelet/lipgloss"

// All Style* values use ANSI 256-color palette indices. They are exported so
// other UI code (TUI, MCP responses) can render identical glyph styling.
var (
	StyleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")) // azure blue
	StyleOnline  = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))            // bright green
	StyleOffline = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))           // bright red
	StyleUnknown = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))           // yellow

	// StyleNone and StyleDim share the same grey. They map to different
	// semantic roles (None = "not applicable" status; Dim = secondary text)
	// so future palette tweaks can diverge without renaming callers.
	StyleNone = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	StyleDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)
