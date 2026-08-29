package ui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"
)

func TestSanitizeTerminalTextRemovesEscapeAndControlSequences(t *testing.T) {
	input := "prod\x1b]52;c;ZXhmaWw=\a\x1b[31m-red\x1b[0m\nnext"
	output := SanitizeTerminalText(input)
	require.NotContains(t, output, "\x1b")
	require.NotContains(t, output, "\a")
	require.NotContains(t, output, "\n")
	require.Contains(t, output, "prod")
	require.Contains(t, output, "next")
}

func TestTruncateWidth_HandlesCJKWithoutOverflow(t *testing.T) {
	got := TruncateWidth("服务器描述abcdef", 10)
	require.LessOrEqual(t, lipgloss.Width(got), 10)
	require.Contains(t, got, "…")
}

func TestPadRightWidth_UsesTerminalCells(t *testing.T) {
	got := PadRightWidth("电脑", 8)
	require.Equal(t, 8, lipgloss.Width(got))
}
