package ui

import (
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func clipANSI(value string, width int) string { return ansi.Truncate(value, width, "…") }
func stripANSI(value string) string           { return ansi.Strip(value) }

// FormTheme keeps the existing setup and action forms visually consistent with
// the inventory browser, including terminals with light backgrounds.
func FormTheme() *huh.Theme {
	t := huh.ThemeBase()
	accent := lipgloss.AdaptiveColor{Light: "30", Dark: "80"}
	muted := lipgloss.AdaptiveColor{Light: "243", Dark: "245"}
	t.Focused.Base = t.Focused.Base.BorderForeground(accent)
	t.Focused.Title = lipgloss.NewStyle().Bold(true).Foreground(accent)
	t.Focused.SelectSelector = lipgloss.NewStyle().Foreground(accent).SetString("› ")
	if ResolveIcons("").Online == "[OK]" {
		t.Focused.SelectSelector = t.Focused.SelectSelector.SetString("> ")
	}
	t.Focused.SelectedOption = lipgloss.NewStyle().Foreground(accent)
	t.Focused.Description = lipgloss.NewStyle().Foreground(muted)
	t.Focused.TextInput.Prompt = lipgloss.NewStyle().Foreground(accent)
	t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(accent)
	t.Blurred.Title = lipgloss.NewStyle().Bold(true)
	t.Blurred.Description = t.Focused.Description
	return t
}
