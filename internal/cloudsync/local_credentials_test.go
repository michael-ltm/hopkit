//go:build !windows

package cloudsync

import (
	"context"
	"os"
	"testing"

	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestRememberVaultOfflineRestartAndAcceptedDeletion(t *testing.T) {
	c, _, pub := loadTestCredential(t, "fixture-pass")
	state, vault, cfg, path := loadTestVault(t, c)
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	report, err := RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	cs, err := store.Resolve(context.Background(), cfg.Servers["local-alias"])
	require.NoError(t, err)
	defer localstore.CloseCredentials(cs)
	signer, err := cs[0].Signer()
	require.NoError(t, err)
	require.Equal(t, pub.Marshal(), signer.PublicKey().Marshal())
	master, err := store.Secret(context.Background(), MasterSecretName(state))
	require.NoError(t, err)
	require.Equal(t, vault.Master, master)
	clear(master)
	// Conflicts leave the last verified local credential intact.
	vault.Data.Conflicts["entry-123"] = Conflict{}
	_, err = RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	_, err = store.Resolve(context.Background(), cfg.Servers["local-alias"])
	require.NoError(t, err)
	delete(vault.Data.Conflicts, "entry-123")
	vault.Data.Deleted["entry-123"] = true
	_, err = RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	_, err = store.Resolve(context.Background(), cfg.Servers["local-alias"])
	require.ErrorIs(t, err, localstore.ErrInactive)
}

func TestStateTokenMigratesWithoutPlaintextFallback(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	state, _, _, path := loadTestVault(t, c)
	state.Token = "fixture-bearer-secret"
	statePath := StatePath(path)
	require.NoError(t, state.Save(statePath)) // legacy uninitialized fixture
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	require.NoError(t, store.Ensure(context.Background()))
	require.NoError(t, state.saveWithStore(statePath, store))
	b, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.NotContains(t, string(b), state.Token)
	require.Contains(t, string(b), "token_ref")
	reopened, err := loadStateWithStore(statePath, store)
	require.NoError(t, err)
	require.Equal(t, state.Token, reopened.Token)
	require.NoError(t, store.Lock(context.Background()))
	require.Error(t, state.saveWithStore(statePath, store))
	still, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.Equal(t, b, still)
	require.NoError(t, store.Unlock(context.Background()))
	require.NoError(t, store.DeleteSecrets(context.Background(), AccountSecretPrefix(state)))
	_, err = loadStateWithStore(statePath, store)
	require.Error(t, err)
}
