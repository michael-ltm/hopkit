package cloudsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
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
	if err := store.Ensure(ctx); err != nil {
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
	for _, alias := range aliases {
		target := cfg.Servers[alias]
		if target == nil {
			continue
		}
		binding := target.CloudEntry
		if binding == "" {
			binding = EntryID(cleanServer(*target))
		}
		if target.CloudVault == owner && v.Data.Deleted[binding] {
			if err := store.Disable(ctx, target); err != nil {
				return report, err
			}
			continue
		}
		entry, ok := matchingAgentEntry(v.Data, target, owner)
		if !ok {
			continue
		}
		var credentials []localstore.Credential
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
			credentials = append(credentials, localstore.Credential{Key: pem.EncodeToMemory(block), Fingerprint: gssh.FingerprintSHA256(signer.PublicKey())})
			clear(block.Bytes)
		}
		if len(passwords) > 1 {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%q: conflicting passwords require a local selection", alias))
			localstore.CloseCredentials(credentials)
			continue
		}
		if len(credentials) > 0 {
			err := store.Put(ctx, target, credentials)
			localstore.CloseCredentials(credentials)
			if err != nil {
				return report, err
			}
			report.Loaded++
		}
	}
	if err := store.SetSecret(ctx, MasterSecretName(state), v.Master); err != nil {
		return report, err
	}
	return report, nil
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
