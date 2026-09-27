//go:build !windows

package commands

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

func TestSetupExplicitPassphrasePromptCanSkipOrImport(t *testing.T) {
	for _, scenario := range []string{"empty key", "wrong key", "correct key", "empty password", "known password"} {
		t.Run(scenario, func(t *testing.T) {
			keyPath, goodPath := filepath.Join(t.TempDir(), "prompted"), filepath.Join(t.TempDir(), "good")
			const secret = "synthetic-prompted-secret"
			_, err := keys.GenerateED25519Encrypted(keyPath, "prompted fixture", secret)
			require.NoError(t, err)
			_, err = keys.GenerateED25519(goodPath, "later usable fixture")
			require.NoError(t, err)
			target := &config.Server{Host: "prompted.invalid", User: "ops", Auth: config.AuthKey, KeyPath: keyPath}
			answer := ""
			switch scenario {
			case "wrong key":
				answer = "synthetic-wrong-secret"
			case "correct key":
				answer = secret
			case "empty password", "known password":
				target.Auth, target.KeyPath = config.AuthPassword, ""
				if scenario == "known password" {
					answer = secret
				}
			}
			good := &config.Server{Host: "later.invalid", User: "ops", Auth: config.AuthKey, KeyPath: goodPath}
			cfg := config.New()
			cfg.Servers["a_prompted"], cfg.Servers["z_usable"] = target, good
			store, cmd, out := migrationSetup(t, cfg)
			require.NoError(t, cmd.Flags().Set("ask-passphrases", "true"))
			require.NoError(t, runMigrationPrompt(t, answer, func() error { return setupLocalCredentials(cmd) }))
			requireMigratedSigner(t, store, good)
			switch scenario {
			case "correct key":
				requireMigratedSigner(t, store, target)
			case "known password":
				cs, err := store.Resolve(context.Background(), target)
				require.NoError(t, err)
				defer localstore.CloseCredentials(cs)
				require.Len(t, cs, 1)
				require.True(t, string(cs[0].Password) == secret)
			default:
				_, err := store.Resolve(context.Background(), target)
				require.ErrorIs(t, err, localstore.ErrNotFound)
				_, err = store.KeyFile(context.Background(), keyPath)
				require.ErrorIs(t, err, localstore.ErrNotFound)
			}
			require.NotContains(t, out.String(), secret)
			require.NotContains(t, out.String(), "synthetic-wrong-secret")
		})
	}
}

func runMigrationPrompt(t *testing.T, answer string, run func() error) error {
	t.Helper()
	master, slave, err := pty.Open()
	require.NoError(t, err)
	defer master.Close()
	defer slave.Close()
	oldStdin := os.Stdin
	os.Stdin = slave
	defer func() { os.Stdin = oldStdin }()
	initial, err := term.GetState(int(slave.Fd()))
	require.NoError(t, err)
	input := make(chan error, 1)
	go func() {
		// ReadPassword disables echo immediately before reading input.
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-deadline.C:
				_ = master.Close()
				input <- errors.New("setup did not open its explicit terminal prompt")
				return
			case <-tick.C:
				state, e := term.GetState(int(slave.Fd()))
				if e != nil {
					_ = master.Close()
					input <- e
					return
				}
				if *state != *initial {
					_, e = io.WriteString(master, answer+"\n")
					input <- e
					return
				}
			}
		}
	}()
	err = run()
	require.NoError(t, <-input)
	return err
}

func TestSetupFirstVaultUnlockDoesNotReviveInactiveTarget(t *testing.T) {
	cfg := config.New()
	inactive := &config.Server{Host: "inactive.invalid", User: "ops", Auth: config.AuthPassword}
	active := &config.Server{Host: "active.invalid", User: "ops", Auth: config.AuthPassword}
	cfg.Servers["inactive"], cfg.Servers["active"] = inactive, active
	store, cmd, out := migrationSetup(t, cfg)
	const phrase = "synthetic-first-unlock-phrase"
	vault, _, err := cloudsync.NewVault("fixture-user", []byte(phrase))
	require.NoError(t, err)
	defer vault.Close()
	_, err = vault.Data.Import(cfg, "fixture-device", false)
	require.NoError(t, err)
	for id := range vault.Data.Entries {
		require.NoError(t, vault.Data.SetPassword(id, "synthetic-vault-password"))
	}
	snap, err := vault.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	state := &cloudsync.State{URL: "http://127.0.0.1:1", Username: "fixture-user", DeviceID: "fixture-device", Base: snap, Draft: snap}
	require.NoError(t, state.Save(cloudsync.StatePath(store.ConfigPath)))
	require.NoError(t, store.Put(context.Background(), inactive, []localstore.Credential{{Password: []byte("synthetic-old-password")}}))
	require.NoError(t, store.Disable(context.Background(), inactive))
	_, err = store.Secret(context.Background(), cloudsync.MasterSecretName(state))
	require.ErrorIs(t, err, localstore.ErrNotFound, "fixture must exercise the first interactive unlock")
	require.NoError(t, runMigrationPrompt(t, phrase, func() error { return setupLocalCredentials(cmd) }))
	_, err = store.Resolve(context.Background(), inactive)
	require.ErrorIs(t, err, localstore.ErrInactive)
	cs, err := store.Resolve(context.Background(), active)
	require.NoError(t, err, "the active target should still import")
	defer localstore.CloseCredentials(cs)
	require.Len(t, cs, 1)
	require.True(t, string(cs[0].Password) == "synthetic-vault-password")
	remembered, err := store.Secret(context.Background(), cloudsync.MasterSecretName(state))
	require.NoError(t, err)
	clear(remembered)
	require.Contains(t, out.String(), "inactive:")
	for _, secret := range []string{phrase, "synthetic-vault-password", "synthetic-old-password"} {
		require.NotContains(t, out.String(), secret)
	}
}
