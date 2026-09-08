package commands

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestUpdatePromptNeverWaitsOnPipedInput(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(bytes.NewBufferString("y\n"))
	cmd.SetErr(&bytes.Buffer{})
	approved, err := confirmUpdate(cmd, "99.0.0")
	require.ErrorContains(t, err, "--yes")
	require.False(t, approved)
	handled, err := offerStartupUpdate(cmd)
	require.NoError(t, err)
	require.False(t, handled)
}

func TestRootVersionFlag(t *testing.T) {
	root := NewRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), Version)
}
