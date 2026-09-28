package cloudsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	gssh "golang.org/x/crypto/ssh"
)

var parseRememberedPrivateKey = parseAgentPrivateKey

func secretDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func AccountSecretPrefix(s *State) string {
	return "cloud/" + secretDigest(strings.TrimRight(s.URL, "/")+"\x00"+s.Username) + "/"
}
func MasterSecretName(s *State) string {
	return AccountSecretPrefix(s) + "master/" + secretDigest(s.Base.RootPublic)
}

// RememberVault creates independent local credentials only from a verified,
// pinned vault and exact target bindings. Cloud/network availability and Agent
// expiry cannot subsequently revoke those credentials. Explicit tombstones can.
func RememberVault(ctx context.Context, state *State, v *Vault, cfg *config.Config, store *localstore.Store) (LoadReport, error) {
	var report LoadReport
	if state == nil || v == nil || cfg == nil || len(v.Master) != 32 || state.URL == "" || state.Username == "" || state.Username != v.Envelope.Account || state.Base.RootPublic == "" || state.Base.RootPublic != v.Public() {
		return report, errors.New("unlocked vault does not match the account and pinned root")
	}
	if err := v.Data.Validate(); err != nil {
		return report, err
	}
	owner := InventoryIdentity(state)
	aliases := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	type parsedKey struct {
		raw any
		err error
	}
	// A credential can serve many exact target bindings. Decrypt its immutable
	// vault bytes once per import, including failed direct attempts. Local-file
	// recovery stays target-specific and is never stored in this cache.
	parsed := make(map[string]parsedKey)
	err := store.Update(ctx, func(local *localstore.Data) error {
		// Verify every existing local selection before staging any imports. This
		// also covers first-time vault unlock and targets absent from this vault.
		inactive := make(map[string]bool)
		for _, alias := range aliases {
			target := cfg.Servers[alias]
			if target == nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			cs, err := local.Resolve(target)
			localstore.CloseCredentials(cs)
			if errors.Is(err, localstore.ErrInactive) {
				inactive[alias] = true
			} else if err != nil && !errors.Is(err, localstore.ErrNotFound) {
				return fmt.Errorf("resolve local credential for %s: %w", alias, err)
			}
		}
		for _, alias := range aliases {
			target := cfg.Servers[alias]
			if target == nil || inactive[alias] {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			binding := target.CloudEntry
			if binding == "" {
				binding = EntryID(cleanServer(*target))
			}
			if target.CloudVault == owner && v.Data.Deleted[binding] {
				if err := local.Disable(target); err != nil {
					return err
				}
				continue
			}
			entry, ok := matchingAgentEntry(v.Data, target, owner)
			if !ok {
				continue
			}
			var credentials []localstore.Credential
			unmatchedFile := false
			passwords := map[string]bool{}
			for _, id := range entry.CredentialIDs {
				c := v.Data.Credentials[id]
				if c.Kind == "password" {
					if entry.Server.Auth != config.AuthPassword {
						continue
					}
					if len(c.Password) > 0 && !passwords[string(c.Password)] {
						passwords[string(c.Password)] = true
						credentials = append(credentials, localstore.Credential{Password: append([]byte(nil), c.Password...)})
					}
					continue
				}
				if c.Kind != "key" {
					continue
				}
				key, known := parsed[id]
				if !known {
					key.raw, key.err = parseRememberedPrivateKey(c.Key, c.Passphrase)
					parsed[id] = key
				}
				raw, err := key.raw, key.err
				if err != nil && target.KeyPath != "" {
					raw, err = recoverLocalAgentKey(state, v.Data, entry, target.KeyPath, c)
				}
				if err != nil {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%q: key needs its original SSH passphrase", alias))
					continue
				}
				signer, err := gssh.NewSignerFromKey(raw)
				if err != nil || (c.Fingerprint != "" && gssh.FingerprintSHA256(signer.PublicKey()) != c.Fingerprint) {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%q: key identity does not match", alias))
					continue
				}
				block, err := gssh.MarshalPrivateKey(raw, "sshm local credential")
				if err != nil {
					continue
				}
				credential := localstore.Credential{Key: pem.EncodeToMemory(block), Fingerprint: gssh.FingerprintSHA256(signer.PublicKey())}
				clear(block.Bytes)
				if target.Auth == config.AuthKey && target.KeyPath != "" {
					if err := credential.VerifyKeyFile(target.KeyPath); err != nil {
						localstore.CloseCredentials([]localstore.Credential{credential})
						if errors.Is(err, localstore.ErrKeyFileChanged) || os.IsNotExist(err) {
							unmatchedFile = true
							continue
						}
						localstore.CloseCredentials(credentials)
						return fmt.Errorf("verify local key file for %s: %w", alias, err)
					}
				}
				credentials = append(credentials, credential)
			}
			if len(passwords) > 1 {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: conflicting passwords require a local selection", alias))
				localstore.CloseCredentials(credentials)
				continue
			}
			if len(credentials) > 0 {
				err := local.Put(target, credentials)
				localstore.CloseCredentials(credentials)
				if err != nil {
					return err
				}
				report.Loaded++
			} else if unmatchedFile {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: no vault key matches the configured local key file; existing local credentials retained", alias))
			}
		}
		return local.SetSecret(MasterSecretName(state), v.Master)
	})
	if err != nil {
		report.Loaded = 0
	}
	return report, err
}

func OpenRemembered(ctx context.Context, state *State, store *localstore.Store) (*Vault, error) {
	master, err := store.Secret(ctx, MasterSecretName(state))
	if err != nil {
		return nil, err
	}
	defer Wipe(master)
	return UnlockMaster(state.Username, state.Draft, master)
}

// RebindRotatedInventory is called only after the old vault authorized a root
// rotation and the server acknowledged the exact new signed snapshot. Preserve
// local route choices and move only targets proved to belong to that old vault.
func RebindRotatedInventory(path string, state *State, v *Vault, previousOwner string) error {
	if state.Base.RootPublic != v.Public() || state.Username != v.Envelope.Account || previousOwner == "" {
		return errors.New("invalid rotated vault binding")
	}
	var updated *config.Config
	err := config.Update(path, func(cfg *config.Config) error {
		updated = cfg
		for _, target := range cfg.Servers {
			if target == nil || target.CloudVault != previousOwner {
				continue
			}
			if _, ok := matchingAgentEntry(v.Data, target, previousOwner); ok {
				target.CloudVault = InventoryIdentity(state)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return config.SaveCloudBindings(path, updated)
}
