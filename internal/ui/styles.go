package ui

import "github.com/charmbracelet/lipgloss"

var (
	StyleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33"))
	StyleOnline  = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	StyleOffline = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	StyleUnknown = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	StyleNone    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	StyleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)
