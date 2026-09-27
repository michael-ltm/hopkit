package localstore

import (
	"context"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemProtectionReopen(t *testing.T) {
	if os.Getenv("SSHM_DEVICEKEY_E2E") != "1" {
		t.Skip("opt in to an isolated native device-protection test")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.toml")
	s := New(path)
	require.NoError(t, s.SetSecret(ctx, "fixture", []byte("synthetic-persistence-proof")))
	reopened := New(path)
	b, e := reopened.Secret(ctx, "fixture")
	require.NoError(t, e)
	defer clear(b)
	require.Equal(t, "synthetic-persistence-proof", string(b))
	require.NoError(t, reopened.Lock(ctx))
	_, e = New(path).Secret(ctx, "fixture")
	require.ErrorIs(t, e, ErrLocked)
	require.NoError(t, reopened.Unlock(ctx))
}
