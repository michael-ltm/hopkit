package localservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncStatusContainsOnlySafeStateAndTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, RecordSyncStatus(path, "sign_in_required"))
	status := readSyncStatus(path)
	require.Equal(t, "sign_in_required", status.State)
	require.Positive(t, status.CheckedAt)
	require.Error(t, RecordSyncStatus(path, "error token=secret"))
	require.Equal(t, "sign_in_required", readSyncStatus(path).State)
	require.NoError(t, os.WriteFile(syncStatusPath(path), []byte(`{"state":"unknown secret content","checked_at":10}`), 0600))
	require.Equal(t, "unknown", readSyncStatus(path).State)
}
