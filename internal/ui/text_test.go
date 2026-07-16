package ui

import (
	"testing"

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
