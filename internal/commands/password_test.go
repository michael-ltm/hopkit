package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordCommand(t *testing.T) {
	posix, err := passwordCommand(passwordPlatformPOSIX)
	require.NoError(t, err)
	require.Equal(t, "passwd", posix)

	windows, err := passwordCommand(passwordPlatformWindows)
	require.NoError(t, err)
	require.Contains(t, windows, "net.exe user")
	require.Contains(t, windows, "$env:USERNAME")

	_, err = passwordCommand("plan9")
	require.Error(t, err)
}

func TestConfirmExactAlias(t *testing.T) {
	cmd := newRmCmd()
	cmd.SetIn(strings.NewReader("pc-e5\n"))
	var out bytes.Buffer
	cmd.SetOut(&out)
	confirmed, err := confirmExactAlias(cmd, "pc-e5", "delete")
	require.NoError(t, err)
	require.True(t, confirmed)
	require.Contains(t, out.String(), `type "pc-e5"`)
}

func TestConfirmExactAliasRejectsMismatch(t *testing.T) {
	cmd := newRmCmd()
	cmd.SetIn(strings.NewReader("wrong\n"))
	cmd.SetOut(&bytes.Buffer{})
	confirmed, err := confirmExactAlias(cmd, "pc-e5", "delete")
	require.NoError(t, err)
	require.False(t, confirmed)
}
