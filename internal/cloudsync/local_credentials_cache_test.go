//go:build !windows

package cloudsync

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func addSharedCredentialTarget(cfg *config.Config, v *Vault, owner, alias, keyPath string) *config.Server {
	entry := v.Data.Entries["entry-123"]
	entry.ID, entry.Aliases, entry.Server.Host = alias, []string{alias}, alias+".invalid"
	v.Data.Entries[alias] = entry
	target := entry.Server
	target.Auth, target.CloudEntry, target.CloudVault, target.KeyPath = config.AuthCloud, entry.ID, owner, keyPath
	cfg.Servers[alias] = &target
	return &target
}

func TestRememberVaultParsesSharedKeyOncePerImport(t *testing.T) {
	c, _, public := loadTestCredential(t, "synthetic-shared-passphrase")
	state, vault, cfg, path := loadTestVault(t, c)
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	for _, alias := range []string{"shared-a", "shared-b", "shared-c"} {
		addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), alias, "")
	}
	old := parseRememberedPrivateKey
	t.Cleanup(func() { parseRememberedPrivateKey = old })
	parses := 0
	parseRememberedPrivateKey = func(key, passphrase []byte) (any, error) {
		parses++
		return old(key, passphrase)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if iteration == 1 {
			// Credential IDs may survive a new accepted snapshot with new bytes.
			// Parsing outcomes must never carry across import calls.
			c, _, public = loadTestCredential(t, "synthetic-replacement-passphrase")
			vault.Data.Credentials["credential-123"] = c
		}
		report, err := RememberVault(context.Background(), state, vault, cfg, store)
		require.NoError(t, err)
		require.Equal(t, 4, report.Loaded)
		require.Equal(t, iteration+1, parses, "shared encrypted credential must decrypt once per import")
		for _, target := range cfg.Servers {
			cs, err := store.Resolve(context.Background(), target)
			require.NoError(t, err)
			require.Len(t, cs, 1)
			signer, err := cs[0].Signer()
			require.NoError(t, err)
			challenge := []byte("shared credential import proof")
			signature, err := signer.Sign(rand.Reader, challenge)
			require.NoError(t, err)
			require.NoError(t, public.Verify(challenge, signature))
			localstore.CloseCredentials(cs)
		}
	}
}

func TestRememberVaultCachesDirectFailureButKeepsRecoveryPerTarget(t *testing.T) {
	for _, recoveredAlias := range []string{"a_recovered", "z_recovered"} {
		t.Run(recoveredAlias, func(t *testing.T) {
			c, raw, public := loadTestCredential(t, "synthetic-original-passphrase")
			c.Passphrase = []byte("synthetic-wrong-passphrase")
			state, vault, cfg, path := loadTestVault(t, c)
			delete(cfg.Servers, "local-alias")
			store := localstore.New(path)
			store.Protector = testutil.NewDeviceProtector()
			block, err := gssh.MarshalPrivateKey(raw, "synthetic-recovery")
			require.NoError(t, err)
			keyPath := filepath.Join(t.TempDir(), "recoverable")
			require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))
			recovered := addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), recoveredAlias, keyPath)
			unavailable := addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), "m_unavailable", keyPath+"-missing")
			old := parseRememberedPrivateKey
			t.Cleanup(func() { parseRememberedPrivateKey = old })
			parses := 0
			parseRememberedPrivateKey = func(key, passphrase []byte) (any, error) {
				parses++
				return old(key, passphrase)
			}
			report, err := RememberVault(context.Background(), state, vault, cfg, store)
			require.NoError(t, err)
			require.Equal(t, 1, parses, "the same failing direct decrypt must not repeat")
			require.Equal(t, 1, report.Loaded)
			require.Len(t, report.Skipped, 1)
			cs, err := store.Resolve(context.Background(), recovered)
			require.NoError(t, err)
			defer localstore.CloseCredentials(cs)
			signer, err := cs[0].Signer()
			require.NoError(t, err)
			require.Equal(t, public.Marshal(), signer.PublicKey().Marshal())
			_, err = store.Resolve(context.Background(), unavailable)
			require.ErrorIs(t, err, localstore.ErrNotFound, "another target's recovered key must not satisfy missing local recovery")
		})
	}
}
