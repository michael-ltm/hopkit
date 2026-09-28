//go:build !windows

package cloudsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/devicekey"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
)

type countingRememberProtector struct {
	devicekey.Protector
	opens int
	err   error
}

func (p *countingRememberProtector) Open(ctx context.Context, id, backend string, data []byte) ([]byte, error) {
	p.opens++
	if p.err != nil {
		return nil, p.err
	}
	return p.Protector.Open(ctx, id, backend, data)
}

func TestRememberVaultBatchOpensDeviceOnceAndPersistsUsableCredentials(t *testing.T) {
	c, _, public := loadTestCredential(t, "")
	state, vault, cfg, path := loadTestVault(t, c)
	for i := 1; i < 38; i++ {
		addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), fmt.Sprintf("shared-%02d", i), "")
	}
	store := localstore.New(path)
	p := &countingRememberProtector{Protector: testutil.NewDeviceProtector()}
	store.Protector = p
	require.NoError(t, store.Ensure(context.Background()))
	p.opens = 0
	report, err := RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	require.Equal(t, 38, report.Loaded)
	require.Equal(t, 1, p.opens, "an import must open device protection once, regardless of target count")

	fresh := localstore.New(path)
	fresh.Protector = p.Protector
	for _, target := range cfg.Servers {
		cs, err := fresh.Resolve(context.Background(), target)
		require.NoError(t, err)
		require.Len(t, cs, 1)
		signer, err := cs[0].Signer()
		require.NoError(t, err)
		challenge := []byte("committed batch signing proof")
		signature, err := signer.Sign(rand.Reader, challenge)
		require.NoError(t, err)
		require.NoError(t, public.Verify(challenge, signature))
		localstore.CloseCredentials(cs)
	}
	master, err := fresh.Secret(context.Background(), MasterSecretName(state))
	require.NoError(t, err)
	require.Equal(t, vault.Master, master)
	clear(master)
}

func TestRememberVaultBatchFailureDoesNotCommitEarlierTargets(t *testing.T) {
	for _, scenario := range []string{"invalid credential count", "invalid target", "replaced unrelated key"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, _ := loadTestCredential(t, "")
			state, vault, cfg, path := loadTestVault(t, c)
			store := localstore.New(path)
			store.Protector = testutil.NewDeviceProtector()
			require.NoError(t, store.SetSecret(context.Background(), "keep", []byte("synthetic-existing-secret")))
			switch scenario {
			case "invalid credential count":
				addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), "z-invalid", "")
				entry := vault.Data.Entries["z-invalid"]
				for len(entry.CredentialIDs) < 33 {
					entry.CredentialIDs = append(entry.CredentialIDs, "credential-123")
				}
				vault.Data.Entries[entry.ID] = entry
			case "invalid target":
				cfg.Servers["z-invalid"] = &config.Server{User: "ops", Auth: config.AuthKey}
			case "replaced unrelated key":
				keyPath := filepath.Join(t.TempDir(), "native-key")
				target := &config.Server{Host: "unrelated.invalid", User: "ops", Auth: config.AuthKey, KeyPath: keyPath}
				cfg.Servers["z-invalid"] = target
				require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{{Key: c.Key}}))
				replacement, _, _ := loadTestCredential(t, "")
				require.NoError(t, os.WriteFile(keyPath, replacement.Key, 0600))
			}
			before, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			report, err := RememberVault(context.Background(), state, vault, cfg, store)
			require.Error(t, err)
			if scenario == "replaced unrelated key" {
				require.ErrorContains(t, err, "configured key file identity changed")
			}
			after, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			require.True(t, bytes.Equal(before, after), "all staged changes must roll back when a later target fails")
			require.Zero(t, report.Loaded, "uncommitted credentials must not be reported as loaded")
		})
	}
}

func TestRememberVaultBatchDoesNotReactivateDisabledCredentials(t *testing.T) {
	c, _, _ := loadTestCredential(t, "")
	state, vault, cfg, path := loadTestVault(t, c)
	store := localstore.New(path)
	store.Protector = testutil.NewDeviceProtector()
	inactive := cfg.Servers["local-alias"]
	require.NoError(t, store.Put(context.Background(), inactive, []localstore.Credential{{Key: c.Key}}))
	require.NoError(t, store.Disable(context.Background(), inactive))
	active := addSharedCredentialTarget(cfg, vault, InventoryIdentity(state), "still-active", "")
	report, err := RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	require.Equal(t, 1, report.Loaded)
	_, err = store.Resolve(context.Background(), inactive)
	require.ErrorIs(t, err, localstore.ErrInactive)
	cs, err := store.Resolve(context.Background(), active)
	require.NoError(t, err)
	localstore.CloseCredentials(cs)
}

func TestRememberVaultBatchUnavailableStoreDoesNotWrite(t *testing.T) {
	for _, scenario := range []string{"locked", "corrupt", "provider unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, _ := loadTestCredential(t, "")
			state, vault, cfg, path := loadTestVault(t, c)
			store := localstore.New(path)
			p := &countingRememberProtector{Protector: testutil.NewDeviceProtector()}
			store.Protector = p
			require.NoError(t, store.Ensure(context.Background()))
			var want error
			switch scenario {
			case "locked":
				require.NoError(t, store.Lock(context.Background()))
				want = localstore.ErrLocked
			case "corrupt":
				require.NoError(t, os.WriteFile(store.Path(), []byte("damaged encrypted store"), 0600))
				want = localstore.ErrCorrupt
			case "provider unavailable":
				p.err, want = devicekey.ErrUnavailable, devicekey.ErrUnavailable
			}
			before, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			_, err = RememberVault(context.Background(), state, vault, cfg, store)
			require.ErrorIs(t, err, want)
			after, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestRememberVaultKeepsExplicitKeyFileSelectionAcrossRepeatedImports(t *testing.T) {
	for _, selectedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("selected-first-%t", selectedFirst), func(t *testing.T) {
			selected, _, public := loadTestCredential(t, "")
			other, _, _ := loadTestCredential(t, "")
			state, vault, cfg, path := loadTestVault(t, selected)
			vault.Data.Credentials["other-device-key"] = other
			entry := vault.Data.Entries["entry-123"]
			entry.CredentialIDs = []string{"other-device-key", "credential-123"}
			if selectedFirst {
				entry.CredentialIDs[0], entry.CredentialIDs[1] = entry.CredentialIDs[1], entry.CredentialIDs[0]
			}
			vault.Data.Entries[entry.ID] = entry
			keyPath := filepath.Join(t.TempDir(), "selected-key")
			require.NoError(t, os.WriteFile(keyPath, selected.Key, 0600))
			target := entry.Server
			target.KeyPath, target.CloudVault = keyPath, InventoryIdentity(state)
			cfg.Servers["local-alias"] = &target
			store := localstore.New(path)
			store.Protector = testutil.NewDeviceProtector()
			for iteration := 0; iteration < 2; iteration++ {
				report, err := RememberVault(context.Background(), state, vault, cfg, store)
				require.NoError(t, err)
				require.Equal(t, 1, report.Loaded)
				cs, err := store.Resolve(context.Background(), &target)
				require.NoError(t, err, "another device's key must not poison the explicit local file binding")
				require.Len(t, cs, 1)
				signer, err := cs[0].Signer()
				require.NoError(t, err)
				challenge := []byte("explicit selected file proof")
				signature, err := signer.Sign(rand.Reader, challenge)
				require.NoError(t, err)
				require.NoError(t, public.Verify(challenge, signature))
				localstore.CloseCredentials(cs)
			}
		})
	}
}

func TestRememberVaultUnavailableKeyFileCannotSelectIncomingKeys(t *testing.T) {
	for _, scenario := range []string{"missing new binding", "missing saved binding", "unrecognized new file"} {
		t.Run(scenario, func(t *testing.T) {
			selected, _, _ := loadTestCredential(t, "")
			state, vault, cfg, path := loadTestVault(t, selected)
			keyPath := filepath.Join(t.TempDir(), "absent-key")
			target := vault.Data.Entries["entry-123"].Server
			target.KeyPath, target.CloudVault = keyPath, InventoryIdentity(state)
			cfg.Servers["local-alias"] = &target
			store := localstore.New(path)
			store.Protector = testutil.NewDeviceProtector()
			var existing localstore.Credential
			if scenario == "missing saved binding" {
				other, _, _ := loadTestCredential(t, "")
				existing = localstore.Credential{Key: other.Key, Fingerprint: other.Fingerprint}
				require.NoError(t, store.Put(context.Background(), &target, []localstore.Credential{existing}))
			} else if scenario == "unrecognized new file" {
				require.NoError(t, os.WriteFile(keyPath, []byte("not a private key"), 0600))
			}
			report, err := RememberVault(context.Background(), state, vault, cfg, store)
			require.NoError(t, err)
			require.Zero(t, report.Loaded)
			require.NotEmpty(t, report.Skipped)
			cs, err := store.Resolve(context.Background(), &target)
			if scenario == "missing saved binding" {
				require.NoError(t, err)
				require.Len(t, cs, 1)
				require.Equal(t, existing.Fingerprint, cs[0].Fingerprint)
				localstore.CloseCredentials(cs)
			} else {
				require.ErrorIs(t, err, localstore.ErrNotFound)
			}
		})
	}
}
