package commands

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/devicekey"
	"github.com/michael-ltm/sshm/internal/keys"
	"github.com/michael-ltm/sshm/internal/localservice"
	"github.com/michael-ltm/sshm/internal/localstore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	gssh "golang.org/x/crypto/ssh"
)

var localCredentialStore = localstore.New

func rememberCloudCredentials(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, path string) (cloudsync.LoadReport, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cloudsync.LoadReport{}, err
	}
	store := localCredentialStore(path)
	// This helper also runs during the first interactive vault unlock. Filter
	// inactive targets before RememberVault can register any active entries.
	for alias, target := range cfg.Servers {
		if target == nil {
			continue
		}
		cs, err := store.Resolve(ctx, target)
		localstore.CloseCredentials(cs)
		if errors.Is(err, localstore.ErrInactive) {
			delete(cfg.Servers, alias)
		} else if err != nil && !errors.Is(err, localstore.ErrNotFound) {
			return cloudsync.LoadReport{}, fmt.Errorf("resolve local credential for %s: %w", alias, err)
		}
	}
	return cloudsync.RememberVault(ctx, s, v, cfg, store)
}

// setupLocalCredentials is only called by the explicit local setup command.
// Existing recovery sidecars can migrate encrypted keys without a prompt.
// Unknown secrets are skipped unless the user explicitly opts into prompting.
func setupLocalCredentials(cmd *cobra.Command) error {
	store := localCredentialStore(configPath())
	if err := store.Ensure(cmd.Context()); err != nil {
		return err
	}
	if _, err := os.Stat(cloudsync.StatePath(configPath())); err == nil {
		s, v, close, err := cloudOpen(cmd)
		if err != nil {
			return err
		}
		// cloudOpen can reuse a remembered master without importing credentials.
		// Re-import the exact accepted snapshot offline, retaining inactive targets.
		report, err := rememberCloudCredentials(cmd.Context(), s, v, configPath())
		for _, reason := range report.Skipped {
			fmt.Fprintln(cmd.ErrOrStderr(), reason)
		}
		close()
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	aliases := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	ask, _ := cmd.Flags().GetBool("ask-passphrases")
	skippedKeys := map[string]string{}
	for _, alias := range aliases {
		target := cfg.Servers[alias]
		if target == nil {
			continue
		}
		if cs, e := store.Resolve(cmd.Context(), target); e == nil {
			localstore.CloseCredentials(cs)
			continue
		} else if errors.Is(e, localstore.ErrInactive) {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: accepted deletion retained; local credential remains inactive.\n", alias)
			continue
		} else if !errors.Is(e, localstore.ErrNotFound) {
			return fmt.Errorf("resolve local credential for %s: %w", alias, e)
		}
		if target.Auth == config.AuthPassword {
			if !ask {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: SSH password is unavailable; skipped. Use --ask-passphrases to enter a known secret locally.\n", alias)
				continue
			}
			pass, e := cloudSecret(cmd, "SSH password for "+alias+" (empty to skip)", false)
			if e != nil {
				clear(pass)
				return e
			}
			if len(pass) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: no SSH password supplied; skipped.\n", alias)
				continue
			}
			e = store.Put(cmd.Context(), target, []localstore.Credential{{Password: pass}})
			clear(pass)
			if e != nil {
				return e
			}
			continue
		}
		if target.KeyPath == "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: no exportable local key; existing external Agent access is retained.\n", alias)
			continue
		}
		path, e := sshpkg.ExpandHome(target.KeyPath)
		if e != nil {
			return e
		}
		if reason, skipped := skippedKeys[path]; skipped {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", alias, reason)
			continue
		}
		reason, e := migrateLocalKey(cmd, store, target, alias, path, ask)
		if e != nil {
			return fmt.Errorf("save local credential for %s: %w", alias, e)
		}
		if reason != "" {
			skippedKeys[path] = reason
			fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", alias, reason)
		}
	}
	return nil
}

// A reason means an unusable source identity was skipped. Errors mean setup
// cannot safely continue (for example a locked, corrupt or unwritable store).
func migrateLocalKey(cmd *cobra.Command, store *localstore.Store, target *config.Server, alias, path string, ask bool) (string, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return "configured key file is unavailable; skipped.", nil
	}
	c := localstore.Credential{Key: key}
	defer func() { localstore.CloseCredentials([]localstore.Credential{c}) }()
	_, err = gssh.ParsePrivateKey(key)
	if err != nil {
		var missing *gssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return "configured key file is malformed or unsupported; skipped.", nil
		}
		c.Passphrase, err = keys.ReadRecovery(path)
		reason := "original SSH key passphrase is unavailable"
		if err == nil {
			_, err = c.Signer()
			if err != nil {
				reason = "recovery passphrase does not unlock the configured key"
			}
		} else if !os.IsNotExist(err) {
			reason = "recovery sidecar is unsafe, unreadable or malformed"
		}
		if err != nil {
			clear(c.Passphrase)
			c.Passphrase = nil
			if !ask {
				return reason + "; skipped. Use --ask-passphrases to enter a known secret locally.", nil
			}
			c.Passphrase, err = cloudSecret(cmd, "Existing SSH key passphrase for "+alias+" (empty to skip)", false)
			if err != nil {
				return "", err
			}
			if len(c.Passphrase) == 0 {
				return "no SSH key passphrase supplied; skipped.", nil
			}
			if _, err = c.Signer(); err != nil {
				return "supplied passphrase does not unlock the configured key; skipped.", nil
			}
		}
	}
	if err = store.RememberKeyFile(cmd.Context(), path, c); err != nil {
		return "", err
	}
	return "", store.Put(cmd.Context(), target, []localstore.Credential{c})
}

// The local service owns its lifetime. This optional worker never closes the
// listener or removes SSH credentials when cloud authentication/network fails.
func runStoredCloudSync(ctx context.Context, path string) {
	delay := 30 * time.Second
	for {
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := syncStoredCloudOnce(attempt, path)
		cancel()
		if ctx.Err() != nil {
			return
		}
		_ = localservice.RecordSyncStatus(path, storedSyncState(err))
		if err == nil {
			delay = 30 * time.Second
		} else {
			delay = min(delay*2, 5*time.Minute)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

var errSyncNotConfigured = errors.New("cloud synchronization is not configured")
var errSyncConflict = errors.New("cloud synchronization needs conflict resolution")

func storedSyncState(err error) string {
	if err == nil {
		return "ready"
	}
	if errors.Is(err, errSyncConflict) {
		return "conflict"
	}
	if errors.Is(err, errSyncNotConfigured) || os.IsNotExist(err) {
		return "not_configured"
	}
	if errors.Is(err, localstore.ErrLocked) {
		return "locked"
	}
	if errors.Is(err, localstore.ErrNotFound) {
		return "migration_required"
	}
	if errors.Is(err, devicekey.ErrUnavailable) {
		return "device_unavailable"
	}
	if errors.Is(err, localstore.ErrCorrupt) || errors.Is(err, cloudsync.ErrUnlock) {
		return "verification_failed"
	}
	var api *cloudsync.APIError
	if errors.As(err, &api) && (api.Status == 401 || api.Status == 403) {
		return "sign_in_required"
	}
	var network *url.Error
	if errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, cloudsync.ErrNetwork) {
		return "offline"
	}
	return "sync_failed"
}
func syncStoredCloudOnce(ctx context.Context, path string) error {
	store := localCredentialStore(path)
	if err := store.CheckLocked(); err != nil {
		return err
	}
	statePath := cloudsync.StatePath(path)
	release, err := cloudsync.Lock(statePath)
	if err != nil {
		return err
	}
	defer release()
	s, err := cloudsync.LoadState(statePath)
	if err != nil {
		return err
	}
	if s.Token == "" {
		return errSyncNotConfigured
	}
	v, err := cloudsync.OpenRemembered(ctx, s, store)
	if err != nil {
		return err
	}
	defer v.Close()
	// Make already-verified offline credentials usable before any network I/O.
	if _, err = rememberCloudCredentials(ctx, s, v, path); err != nil {
		return err
	}
	if err = s.Sync(ctx, v, statePath); err != nil {
		return err
	}
	// Apply accepted deletions against the old local list before publishing.
	if _, err = rememberCloudCredentials(ctx, s, v, path); err != nil {
		return err
	}
	if _, err = cloudsync.PublishInventory(path, s, v.Data); err != nil {
		return err
	}
	if _, err = rememberCloudCredentials(ctx, s, v, path); err != nil {
		return err
	}
	if len(v.Data.Conflicts) > 0 {
		return errSyncConflict
	}
	return s.Heartbeat(ctx, Version)
}

func generateLocalKey(cmd *cobra.Command, path, comment, passphrase string) (string, error) {
	store := localCredentialStore(configPath())
	if !store.Enabled() || passphrase == "" {
		return keys.GenerateED25519Encrypted(path, comment, passphrase)
	}
	return keys.GenerateED25519Protected(path, comment, passphrase, func(key []byte) error {
		return store.RememberKeyFile(cmd.Context(), path, localstore.Credential{Key: key, Passphrase: []byte(passphrase)})
	})
}
func rememberGeneratedKey(cmd *cobra.Command, path, passphrase string) (bool, error) {
	store := localCredentialStore(configPath())
	if !store.Enabled() {
		return false, nil
	} // explicit legacy --passphrase-file
	c, err := store.KeyFile(cmd.Context(), path)
	defer localstore.CloseCredentials([]localstore.Credential{c})
	return true, err
}

func managedPairKey(path string) (string, bool, error) {
	store := localCredentialStore(configPath())
	if !store.Enabled() {
		return "", false, nil
	}
	c, err := store.KeyFile(context.Background(), path)
	if errors.Is(err, localstore.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", true, err
	}
	defer localstore.CloseCredentials([]localstore.Credential{c})
	signer, err := c.Signer()
	if err != nil {
		return "", true, err
	}
	public, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", true, err
	}
	declared, _, _, _, err := gssh.ParseAuthorizedKey(public)
	if err != nil || gssh.FingerprintSHA256(declared) != gssh.FingerprintSHA256(signer.PublicKey()) {
		return "", true, errors.New("configured public key differs from saved local credential")
	}
	// Exercise the same replacement check used by real SSH authentication.
	if !sshpkg.HasLocalAuth(&config.Server{Host: "pair-preflight", User: "pair-preflight", Auth: config.AuthKey, KeyPath: path}, sshpkg.BuildOpts{LocalStore: store}) {
		return "", true, errors.New("saved pairing key is unavailable or its file identity changed")
	}
	return string(gssh.MarshalAuthorizedKey(signer.PublicKey())), true, nil
}
