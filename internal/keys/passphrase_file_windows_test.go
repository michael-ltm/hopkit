//go:build windows

package keys

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReadPassphraseFileWindowsFailsClosed(t *testing.T) {
	b, err := ReadPassphraseFile("any-path")
	require.Empty(t, b)
	require.ErrorContains(t, err, "interactive")
	require.ErrorContains(t, err, "Windows")
}
