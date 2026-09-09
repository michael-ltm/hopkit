package cloudsync

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
)

// LoadReport is a non-secret summary of identities loaded into the session agent.
type LoadReport struct {
	Loaded  int      `json:"loaded"`
	Skipped []string `json:"skipped,omitempty"`
}

// LoadMatchingKeysIntoAgent decrypts vault-held keys, loads them into the
// current SSH agent, and writes public identities for local aliases. It never
// rewrites private key files, sidecars, or the vault.
func LoadMatchingKeysIntoAgent(v *Vault, cfg *config.Config) (LoadReport, error) {
	var report LoadReport
	if v == nil {
		return report, nil
	}
	if err := keystore.EnsureAgent(); err != nil {
		return report, err
	}
	loaded := map[string]gssh.PublicKey{}
	for _, cred := range v.Data.Credentials {
		if cred.Kind != "key" {
			continue
		}
		raw, pub, err := rawSignerMaterial(cred)
		if err != nil {
			continue
		}
		id := gssh.FingerprintSHA256(pub)
		if loaded[id] != nil {
			continue
		}
		if err = loadAndProve(raw, pub); err != nil {
			continue
		}
		loaded[id] = pub
		report.Loaded++
	}
	if cfg == nil {
		return report, nil
	}
	aliases := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	seen := map[string]bool{}
	for _, alias := range aliases {
		server := cfg.Servers[alias]
		if server == nil {
			continue
		}
		pub, err := localPublicKey(alias, server, v)
		if err != nil {
			if server.Auth == config.AuthKey && server.KeyPath != "" {
				report.Skipped = append(report.Skipped, alias+": unlock material unavailable")
			}
			continue
		}
		id := gssh.FingerprintSHA256(pub)
		if loaded[id] == nil {
			if server.KeyPath != "" {
				path, expErr := sshpkg.ExpandHome(server.KeyPath)
				if expErr == nil && !seen[path] {
					seen[path] = true
					local, readErr := os.ReadFile(path)
					if readErr == nil {
						raw, rawErr := rawKeyForIdentity(local, pub, v.Data.Credentials)
						if rawErr == nil && loadAndProve(raw, pub) == nil {
							loaded[id] = pub
							report.Loaded++
						}
					}
				}
			}
		}
		if err := writeAliasPublicKey(alias, pub); err != nil {
			report.Skipped = append(report.Skipped, alias+": "+err.Error())
		}
	}
	return report, nil
}

func rawSignerMaterial(cred Credential) (any, gssh.PublicKey, error) {
	var raw any
	var err error
	if len(cred.Passphrase) > 0 {
		raw, err = gssh.ParseRawPrivateKeyWithPassphrase(cred.Key, cred.Passphrase)
	} else {
		raw, err = gssh.ParseRawPrivateKey(cred.Key)
	}
	if err != nil {
		return nil, nil, err
	}
	signer, err := gssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, signer.PublicKey(), nil
}

func localPublicKey(alias string, server *config.Server, v *Vault) (gssh.PublicKey, error) {
	if server.KeyPath != "" {
		path, err := sshpkg.ExpandHome(server.KeyPath)
		if err == nil {
			local, readErr := os.ReadFile(path)
			if readErr == nil {
				if pub, pubErr := publicIdentity(local, path); pubErr == nil {
					return pub, nil
				}
			}
		}
	}
	for _, entry := range v.Data.Entries {
		named := false
		for _, name := range entry.Aliases {
			if name == alias {
				named = true
				break
			}
		}
		if server.CloudEntry != "" && entry.ID != server.CloudEntry && !named {
			continue
		}
		if server.CloudEntry == "" && !named && !sameCloudRoute(*server, entry.Server) {
			continue
		}
		for _, id := range entry.CredentialIDs {
			cred := v.Data.Credentials[id]
			if _, pub, err := rawSignerMaterial(cred); err == nil {
				return pub, nil
			}
			if pub, err := publicIdentity(cred.Key, ""); err == nil {
				return pub, nil
			}
		}
	}
	return nil, errors.New("public identity unavailable")
}

func writeAliasPublicKey(alias string, pub gssh.PublicKey) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh", "sshm-keys")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, alias+".pub")
	body := gssh.MarshalAuthorizedKey(pub)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return nil
	}
	return os.WriteFile(path, body, 0644)
}

func publicIdentity(local []byte, path string) (gssh.PublicKey, error) {
	if raw, err := gssh.ParseRawPrivateKey(local); err == nil {
		signer, err := gssh.NewSignerFromKey(raw)
		if err != nil {
			return nil, err
		}
		return signer.PublicKey(), nil
	} else {
		var missing *gssh.PassphraseMissingError
		if errors.As(err, &missing) && missing.PublicKey != nil {
			return missing.PublicKey, nil
		}
	}
	if path == "" {
		return nil, errors.New("public identity unavailable")
	}
	data, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, err
	}
	pub, _, _, rest, err := gssh.ParseAuthorizedKey(data)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 || pub == nil {
		return nil, errors.New("public identity unavailable")
	}
	return pub, nil
}

func rawKeyForIdentity(local []byte, pub gssh.PublicKey, creds map[string]Credential) (any, error) {
	if raw, err := gssh.ParseRawPrivateKey(local); err == nil {
		return raw, nil
	}
	if pub == nil {
		return nil, errors.New("public identity unavailable")
	}
	want := pub.Marshal()
	fingerprint := gssh.FingerprintSHA256(pub)
	for _, cred := range creds {
		if cred.Kind == "password" && cred.Password != "" {
			raw, err := gssh.ParseRawPrivateKeyWithPassphrase(local, []byte(cred.Password))
			if err == nil {
				signer, err := gssh.NewSignerFromKey(raw)
				if err == nil && bytes.Equal(signer.PublicKey().Marshal(), want) {
					return raw, nil
				}
			}
			continue
		}
		if cred.Kind != "key" {
			continue
		}
		if cred.Fingerprint != "" && cred.Fingerprint != fingerprint {
			continue
		}
		candidates := []struct {
			key, pass []byte
		}{
			{local, cred.Passphrase},
			{cred.Key, cred.Passphrase},
			{cred.Key, nil},
		}
		for _, c := range candidates {
			if len(c.key) == 0 {
				continue
			}
			var raw any
			var err error
			if len(c.pass) > 0 {
				raw, err = gssh.ParseRawPrivateKeyWithPassphrase(c.key, c.pass)
			} else {
				raw, err = gssh.ParseRawPrivateKey(c.key)
			}
			if err != nil {
				continue
			}
			signer, err := gssh.NewSignerFromKey(raw)
			if err == nil && bytes.Equal(signer.PublicKey().Marshal(), want) {
				return raw, nil
			}
		}
	}
	return nil, errors.New("unlock material unavailable")
}
