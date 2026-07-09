package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootRegistersTransferCommands(t *testing.T) {
	root := NewRoot()

	upload, _, err := root.Find([]string{"upload"})
	require.NoError(t, err)
	require.Equal(t, "upload", upload.Name())

	download, _, err := root.Find([]string{"download"})
	require.NoError(t, err)
	require.Equal(t, "download", download.Name())
}
