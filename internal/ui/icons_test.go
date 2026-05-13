package ui

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIcons_Unicode(t *testing.T) {
	ic := UnicodeIcons()
	require.Equal(t, "✓", ic.Online)
	require.Equal(t, "✗", ic.Offline)
	require.Equal(t, "◌", ic.Unknown)
	require.Equal(t, "—", ic.None)
	require.Equal(t, "🔒", ic.AuthKey)
	require.Equal(t, "🔑", ic.AuthPassword)
}

func TestIcons_ASCII(t *testing.T) {
	ic := ASCIIIcons()
	require.Equal(t, "[OK]", ic.Online)
	require.Equal(t, "[X]", ic.Offline)
	require.Equal(t, "[?]", ic.Unknown)
	require.Equal(t, "[--]", ic.None)
	require.Equal(t, "[K]", ic.AuthKey)
	require.Equal(t, "[P]", ic.AuthPassword)
}

func TestResolveIcons_ExplicitASCII(t *testing.T) {
	ic := ResolveIcons("ascii")
	require.Equal(t, "[OK]", ic.Online)
}

func TestResolveIcons_ExplicitUnicode(t *testing.T) {
	ic := ResolveIcons("unicode")
	require.Equal(t, "✓", ic.Online)
}
