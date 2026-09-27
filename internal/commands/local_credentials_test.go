package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestPairGeneratedKeyPersistsWithoutPassphrasePromptOrAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	store := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	store.Protector = testutil.NewDeviceProtector()
	previous, oldConfig := localCredentialStore, flagConfigPath
	localCredentialStore = func(string) *localstore.Store { return store }
	flagConfigPath = store.ConfigPath
	t.Cleanup(func() { localCredentialStore, flagConfigPath = previous, oldConfig })
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "absent"))
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	addKeyPassphraseFlag(cmd)
	var out bytes.Buffer
	cmd.SetOut(&out)
	public, generated, err := preparePairKey(cmd, "fixture", path, false)
	require.NoError(t, err)
	require.True(t, generated)
	require.NotEmpty(t, public)
	key, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = gssh.ParsePrivateKey(key)
	var missing *gssh.PassphraseMissingError
	require.True(t, errors.As(err, &missing), "private key file must remain encrypted")
	fresh := localstore.New(store.ConfigPath)
	fresh.Protector = store.Protector
	require.True(t, sshpkg.HasLocalAuth(&config.Server{Host: "fixture", User: "fixture", Auth: config.AuthKey, KeyPath: path}, sshpkg.BuildOpts{LocalStore: fresh}))
	publicAgain, generated, err := preparePairKey(cmd, "fixture", path, false)
	require.NoError(t, err)
	require.False(t, generated)
	require.Equal(t, public, publicAgain)
	require.NoFileExists(t, path+".passphrase")
}

func TestLockedPasswordExecDiagnosesDeviceLock(t *testing.T) {
	store := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	store.Protector = testutil.NewDeviceProtector()
	target := &config.Server{Host: "fixture.invalid", User: "ops", Port: 22, Auth: config.AuthPassword}
	cfg := config.New()
	cfg.Servers["fixture"] = target
	require.NoError(t, config.Save(store.ConfigPath, cfg))
	require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{{Password: []byte("test-secret")}}))
	require.NoError(t, store.Lock(context.Background()))
	previous := flagConfigPath
	t.Cleanup(func() { flagConfigPath = previous })
	root := NewRoot()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--config", store.ConfigPath, "exec", "fixture", "true"})
	require.ErrorContains(t, root.Execute(), "service unlock")
	_, err := dialInteractive("fixture", target, false, store.ConfigPath)
	require.ErrorContains(t, err, "service unlock")
}

func TestStoredCloudFailuresLeaveIndependentCredentialsUsable(t *testing.T) {
	for _, scenario := range []string{"unauthorized", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "timeout" {
					<-r.Context().Done()
					return
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			}))
			defer server.Close()
			store := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
			store.Protector = testutil.NewDeviceProtector()
			previous := localCredentialStore
			localCredentialStore = func(string) *localstore.Store { return store }
			t.Cleanup(func() { localCredentialStore = previous })
			cfg := config.New()
			target := &config.Server{Host: "fixture.invalid", User: "ops", Auth: config.AuthPassword}
			cfg.Servers["fixture"] = target
			require.NoError(t, config.Save(store.ConfigPath, cfg))
			vault, _, err := cloudsync.NewVault("fixture-user", []byte("fixture-unlock-phrase"))
			require.NoError(t, err)
			defer vault.Close()
			_, err = vault.Data.Import(cfg, "fixture-device", false)
			require.NoError(t, err)
			for id := range vault.Data.Entries {
				require.NoError(t, vault.Data.SetPassword(id, "fixture-ssh-password"))
			}
			snap, err := vault.Snapshot(0, cloudsync.RandomID())
			require.NoError(t, err)
			state := &cloudsync.State{URL: server.URL, Username: "fixture-user", Token: "synthetic-token", DeviceID: "fixture-device", Base: snap, Draft: snap}
			require.NoError(t, state.Save(cloudsync.StatePath(store.ConfigPath)))
			_, err = cloudsync.RememberVault(context.Background(), state, vault, cfg, store)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			err = syncStoredCloudOnce(ctx, store.ConfigPath)
			cancel()
			require.Error(t, err)
			if scenario == "unauthorized" {
				require.Equal(t, "sign_in_required", storedSyncState(err))
			} else {
				require.Equal(t, "offline", storedSyncState(err))
			}
			fresh := localstore.New(store.ConfigPath)
			fresh.Protector = store.Protector
			require.True(t, sshpkg.HasLocalAuth(target, sshpkg.BuildOpts{LocalStore: fresh}))
		})
	}
}

func TestStoredSyncReportsAcceptedConflictWithoutLosingNativePassword(t *testing.T) {
	if os.Getenv("SSHM_DEVICEKEY_E2E") != "1" {
		t.Skip("opt in to native encrypted state persistence")
	}
	store := localstore.New(filepath.Join(t.TempDir(), "config.toml"))
	cfg := config.New()
	target := &config.Server{Host: "fixture.invalid", User: "ops", Auth: config.AuthPassword}
	cfg.Servers["fixture"] = target
	cfg.Default = "fixture"
	require.NoError(t, config.Save(store.ConfigPath, cfg))
	vault, _, err := cloudsync.NewVault("fixture-user", []byte("fixture-unlock-phrase"))
	require.NoError(t, err)
	defer vault.Close()
	_, err = vault.Data.Import(cfg, "fixture-device", false)
	require.NoError(t, err)
	for id := range vault.Data.Entries {
		require.NoError(t, vault.Data.SetPassword(id, "fixture-ssh-password"))
	}
	initial, err := vault.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	initial.Revision = 1
	remote, err := cloudsync.UnlockMaster("fixture-user", initial, vault.Master)
	require.NoError(t, err)
	defer remote.Close()
	for id, e := range remote.Data.Entries {
		copy := e
		remote.Data.Conflicts[id] = cloudsync.Conflict{Local: &copy, Remote: &copy}
	}
	next, err := remote.Snapshot(1, cloudsync.RandomID())
	require.NoError(t, err)
	next.Revision = 2
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(next) }))
	defer server.Close()
	state := &cloudsync.State{URL: server.URL, Username: "fixture-user", DeviceID: "fixture-device", Token: "synthetic-token", Base: initial, Draft: initial}
	_, err = cloudsync.RememberVault(context.Background(), state, vault, cfg, store)
	require.NoError(t, err)
	require.NoError(t, state.Save(cloudsync.StatePath(store.ConfigPath)))
	err = syncStoredCloudOnce(context.Background(), store.ConfigPath)
	require.ErrorIs(t, err, errSyncConflict)
	require.Equal(t, "conflict", storedSyncState(err))
	updated, err := config.Load(store.ConfigPath)
	require.NoError(t, err)
	require.True(t, sshpkg.HasLocalAuth(updated.Servers["fixture"], sshpkg.BuildOpts{ConfigPath: store.ConfigPath}))
}
