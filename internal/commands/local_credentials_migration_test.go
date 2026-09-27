package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/devicekey"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func migrationSetup(t *testing.T, cfg *config.Config) (*localstore.Store, *cobra.Command, *bytes.Buffer) {
	t.Helper()
	store := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	store.Protector = testutil.NewDeviceProtector()
	require.NoError(t, config.Save(store.ConfigPath, cfg))
	previous, oldConfig := localCredentialStore, flagConfigPath
	localCredentialStore = func(string) *localstore.Store { return store }
	flagConfigPath = store.ConfigPath
	t.Cleanup(func() { localCredentialStore, flagConfigPath = previous, oldConfig })
	cmd := &cobra.Command{}
	cmd.Flags().Bool("ask-passphrases", false, "")
	cmd.SetContext(context.Background())
	cmd.SetIn(bytes.NewBuffer(nil))
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	return store, cmd, out
}

func requireMigratedSigner(t *testing.T, store *localstore.Store, target *config.Server) {
	t.Helper()
	fresh := localstore.New(store.ConfigPath)
	fresh.Protector = store.Protector
	cs, err := fresh.Resolve(context.Background(), target)
	require.NoError(t, err)
	defer localstore.CloseCredentials(cs)
	require.Len(t, cs, 1)
	signer, err := cs[0].Signer()
	require.NoError(t, err)
	challenge := []byte("independent setup migration signing proof")
	sig, err := signer.Sign(rand.Reader, challenge)
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify(challenge, sig))
}

func TestSetupMigratesLegacyRecoveryWithoutPromptAndPreservesSources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sidecar ACL validation is unavailable on Windows")
	}
	keyPath := filepath.Join(t.TempDir(), "legacy")
	const secret = "#synthetic-legacy-sidecar-secret"
	_, err := keys.GenerateED25519Encrypted(keyPath, "migration fixture", secret)
	require.NoError(t, err)
	_, err = keys.WriteRecovery(keyPath, secret)
	require.NoError(t, err)
	sources := map[string][]byte{}
	for _, path := range []string{keyPath, keyPath + ".pub", keyPath + ".passphrase"} {
		sources[path], err = os.ReadFile(path)
		require.NoError(t, err)
	}
	cfg := config.New()
	target := &config.Server{Host: "fixture.invalid", User: "ops", Auth: config.AuthKey, KeyPath: keyPath}
	cfg.Servers["legacy"] = target
	store, cmd, out := migrationSetup(t, cfg)
	require.NoError(t, setupLocalCredentials(cmd))
	requireMigratedSigner(t, store, target)
	require.NoError(t, setupLocalCredentials(cmd), "repeat setup needs no prompt")
	for path, before := range sources {
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.True(t, bytes.Equal(before, after), "migration must preserve source files")
	}
	require.NotContains(t, out.String(), secret)
	require.NotContains(t, out.String(), "PRIVATE KEY")
	data, err := store.Read(context.Background())
	require.NoError(t, err)
	defer data.Close()
	require.Len(t, data.KeyFiles, 1)
	require.Len(t, data.Connections, 1)
}

func TestSetupSkipsUnusableIdentityAndMigratesLaterKey(t *testing.T) {
	for _, scenario := range []string{"missing sidecar", "wrong sidecar", "malformed key", "malformed sidecar", "unsafe sidecar", "symlink sidecar", "password missing"} {
		t.Run(scenario, func(t *testing.T) {
			if runtime.GOOS == "windows" && (scenario == "unsafe sidecar" || scenario == "symlink sidecar") {
				t.Skip("POSIX file safety")
			}
			dir := t.TempDir()
			badPath, goodPath := filepath.Join(dir, "bad"), filepath.Join(dir, "good")
			_, err := keys.GenerateED25519Encrypted(badPath, "unusable fixture", "synthetic-unknown-secret")
			require.NoError(t, err)
			bad := &config.Server{Host: "bad.invalid", User: "ops", Auth: config.AuthKey, KeyPath: badPath}
			switch scenario {
			case "wrong sidecar":
				_, err = keys.WriteRecovery(badPath, "synthetic-wrong-secret")
				require.NoError(t, err)
			case "malformed key":
				require.NoError(t, os.WriteFile(badPath, []byte("not an SSH private key"), 0600))
			case "malformed sidecar":
				require.NoError(t, os.WriteFile(badPath+".passphrase", []byte("one\ntwo\n"), 0600))
			case "unsafe sidecar":
				require.NoError(t, os.WriteFile(badPath+".passphrase", []byte("synthetic-unknown-secret\n"), 0600))
				require.NoError(t, os.Chmod(badPath+".passphrase", 0644))
			case "symlink sidecar":
				secretPath := filepath.Join(dir, "separate-secret")
				require.NoError(t, os.WriteFile(secretPath, []byte("synthetic-unknown-secret\n"), 0600))
				require.NoError(t, os.Symlink(secretPath, badPath+".passphrase"))
			case "password missing":
				bad.Auth, bad.KeyPath = config.AuthPassword, ""
			}
			_, err = keys.GenerateED25519(goodPath, "later usable fixture")
			require.NoError(t, err)
			good := &config.Server{Host: "good.invalid", User: "ops", Auth: config.AuthKey, KeyPath: goodPath}
			cfg := config.New()
			cfg.Servers["a_unusable"], cfg.Servers["z_usable"] = bad, good
			store, cmd, out := migrationSetup(t, cfg)
			require.NoError(t, setupLocalCredentials(cmd))
			requireMigratedSigner(t, store, good)
			_, err = store.Resolve(context.Background(), bad)
			require.ErrorIs(t, err, localstore.ErrNotFound)
			_, err = store.KeyFile(context.Background(), badPath)
			require.ErrorIs(t, err, localstore.ErrNotFound)
			require.Contains(t, out.String(), "a_unusable:")
			require.NotContains(t, out.String(), "synthetic-unknown-secret")
			require.NotContains(t, out.String(), "synthetic-wrong-secret")
		})
	}
}

func TestSetupReimportsRememberedVaultOffline(t *testing.T) {
	cfg := config.New()
	target := &config.Server{Host: "offline.invalid", User: "ops", Auth: config.AuthPassword}
	cfg.Servers["offline"] = target
	store, cmd, out := migrationSetup(t, cfg)
	vault, _, err := cloudsync.NewVault("fixture-user", []byte("synthetic-vault-phrase"))
	require.NoError(t, err)
	defer vault.Close()
	_, err = vault.Data.Import(cfg, "fixture-device", false)
	require.NoError(t, err)
	for id := range vault.Data.Entries {
		require.NoError(t, vault.Data.SetPassword(id, "synthetic-ssh-password"))
	}
	snap, err := vault.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	state := &cloudsync.State{URL: "http://127.0.0.1:1", Username: "fixture-user", DeviceID: "fixture-device", Base: snap, Draft: snap}
	require.NoError(t, state.Save(cloudsync.StatePath(store.ConfigPath)))
	require.NoError(t, store.SetSecret(context.Background(), cloudsync.MasterSecretName(state), vault.Master))
	require.NoError(t, setupLocalCredentials(cmd))
	fresh := localstore.New(store.ConfigPath)
	fresh.Protector = store.Protector
	cs, err := fresh.Resolve(context.Background(), target)
	require.NoError(t, err)
	defer localstore.CloseCredentials(cs)
	require.Len(t, cs, 1)
	require.True(t, bytes.Equal(cs[0].Password, []byte("synthetic-ssh-password")))
	require.NotContains(t, out.String(), "synthetic-ssh-password")
}

// The protected store is real; this wrapper changes availability between the
// initial Ensure and later Resolve to catch accidental source-key fallback.
type migrationProtector struct {
	devicekey.Protector
	opens          int
	afterFirstOpen func()
	openError      error
}

func (p *migrationProtector) Open(ctx context.Context, id, backend string, data []byte) ([]byte, error) {
	p.opens++
	if p.opens > 1 && p.openError != nil {
		return nil, p.openError
	}
	key, err := p.Protector.Open(ctx, id, backend, data)
	if p.opens == 1 && err == nil && p.afterFirstOpen != nil {
		p.afterFirstOpen()
	}
	return key, err
}

func TestSetupFailsClosedWhenStoreBecomesUnavailable(t *testing.T) {
	for _, scenario := range []string{"locked", "corrupt", "device unavailable", "storage permissions"} {
		t.Run(scenario, func(t *testing.T) {
			if scenario == "storage permissions" && runtime.GOOS == "windows" {
				t.Skip("POSIX storage permission fixture")
			}
			keyPath := filepath.Join(t.TempDir(), "usable")
			_, err := keys.GenerateED25519Encrypted(keyPath, "must not import", "synthetic-unavailable-store-secret")
			require.NoError(t, err)
			cfg := config.New()
			cfg.Servers["fixture"] = &config.Server{Host: "fixture.invalid", User: "ops", Auth: config.AuthKey, KeyPath: keyPath}
			store, cmd, out := migrationSetup(t, cfg)
			require.NoError(t, store.Ensure(context.Background()))
			original, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			p := &migrationProtector{Protector: store.Protector}
			var want error
			switch scenario {
			case "locked":
				want = localstore.ErrLocked
				p.afterFirstOpen = func() { require.NoError(t, os.WriteFile(store.Path()+".locked", []byte("locked\n"), 0600)) }
			case "corrupt":
				want = localstore.ErrCorrupt
				p.afterFirstOpen = func() { require.NoError(t, os.WriteFile(store.Path(), []byte("damaged encrypted store"), 0600)) }
			case "device unavailable":
				want = devicekey.ErrUnavailable
				p.openError = want
			case "storage permissions":
				p.afterFirstOpen = func() { require.NoError(t, os.Chmod(store.Path(), 0644)) }
			}
			store.Protector = p
			err = setupLocalCredentials(cmd)
			if want != nil {
				require.ErrorIs(t, err, want)
			} else {
				require.Error(t, err)
			}
			require.NotContains(t, out.String(), "passphrase")
			after, err := os.ReadFile(store.Path())
			require.NoError(t, err)
			if scenario == "corrupt" {
				require.Equal(t, "damaged encrypted store", string(after))
			} else {
				require.True(t, bytes.Equal(original, after), "setup must not overwrite unavailable storage")
			}
		})
	}
}

func TestSetupPreservesAcceptedDeletion(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "inactive")
	_, err := keys.GenerateED25519(keyPath, "inactive fixture")
	require.NoError(t, err)
	cfg := config.New()
	target := &config.Server{Host: "inactive.invalid", User: "ops", Auth: config.AuthKey, KeyPath: keyPath}
	cfg.Servers["inactive"] = target
	store, cmd, out := migrationSetup(t, cfg)
	require.NoError(t, store.Disable(context.Background(), target))
	require.NoError(t, setupLocalCredentials(cmd))
	_, err = store.Resolve(context.Background(), target)
	require.ErrorIs(t, err, localstore.ErrInactive)
	_, err = store.KeyFile(context.Background(), keyPath)
	require.ErrorIs(t, err, localstore.ErrNotFound)
	require.Contains(t, out.String(), "inactive:")
}

func TestSetupRememberedVaultDoesNotReviveInactiveTarget(t *testing.T) {
	cfg := config.New()
	target := &config.Server{Host: "inactive.invalid", User: "ops", Auth: config.AuthPassword}
	cfg.Servers["inactive"] = target
	store, cmd, out := migrationSetup(t, cfg)
	vault, _, err := cloudsync.NewVault("fixture-user", []byte("synthetic-vault-phrase"))
	require.NoError(t, err)
	defer vault.Close()
	_, err = vault.Data.Import(cfg, "fixture-device", false)
	require.NoError(t, err)
	for id := range vault.Data.Entries {
		require.NoError(t, vault.Data.SetPassword(id, "synthetic-inactive-password"))
	}
	snap, err := vault.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	state := &cloudsync.State{URL: "http://127.0.0.1:1", Username: "fixture-user", DeviceID: "fixture-device", Base: snap, Draft: snap}
	require.NoError(t, state.Save(cloudsync.StatePath(store.ConfigPath)))
	require.NoError(t, store.SetSecret(context.Background(), cloudsync.MasterSecretName(state), vault.Master))
	require.NoError(t, store.Disable(context.Background(), target))
	require.NoError(t, setupLocalCredentials(cmd))
	_, err = store.Resolve(context.Background(), target)
	require.ErrorIs(t, err, localstore.ErrInactive)
	require.Contains(t, out.String(), "inactive:")
	require.NotContains(t, out.String(), "synthetic-inactive-password")
}
