package cloudsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type KeyMigration struct {
	Alias       string `json:"alias"`
	Path        string `json:"path"`
	Original    string `json:"original_credential"`
	Recovery    string `json:"recovery_backup,omitempty"`
	Replacement string `json:"replacement_credential,omitempty"`
	Status      string `json:"status"`
}
type HardenReport struct {
	Encrypted       int      `json:"encrypted"`
	RecoveryRemoved int      `json:"recovery_removed"`
	AgentLoaded     int      `json:"agent_loaded"`
	Retained        []string `json:"retained,omitempty"`
}
type keyPlan struct {
	receipt                              KeyMigration
	original, sidecar, replacement, pass []byte
	raw                                  any
	public                               gssh.PublicKey
}

// HardenLocal backs up recoverable key material inside the already unlocked
// E2EE vault before any local mutation. It never changes the public identity.
func (s *State) HardenLocal(ctx context.Context, v *Vault, cfg *config.Config, statePath string) (HardenReport, error) {
	var report HardenReport
	if err := keystore.EnsureAgent(); err != nil {
		return report, err
	}
	aliases := make([]string, 0, len(cfg.Servers))
	for a := range cfg.Servers {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	seen := map[string]bool{}
	var plans []*keyPlan
	defer func() {
		for _, p := range plans {
			Wipe(p.original)
			Wipe(p.sidecar)
			Wipe(p.replacement)
			Wipe(p.pass)
		}
	}()
	for _, alias := range aliases {
		server := cfg.Servers[alias]
		if server == nil || server.CloudEntry != "" || server.Auth != config.AuthKey {
			continue
		}
		path, err := sshpkg.ExpandHome(server.KeyPath)
		if err != nil {
			return report, err
		}
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
			report.Retained = append(report.Retained, alias+": not a regular readable key")
			continue
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return report, err
		}
		p := &keyPlan{receipt: KeyMigration{Alias: alias, Path: path}, original: original}
		plans = append(plans, p)
		p.raw, err = gssh.ParseRawPrivateKey(original)
		var missing *gssh.PassphraseMissingError
		if err == nil {
			signer, e := gssh.NewSignerFromKey(p.raw)
			if e != nil {
				return report, e
			}
			p.public = signer.PublicKey()
		} else if errors.As(err, &missing) {
			p.public = missing.PublicKey
		} else {
			report.Retained = append(report.Retained, alias+": unsupported key")
			continue
		}
		if p.public == nil {
			report.Retained = append(report.Retained, alias+": public identity unavailable")
			continue
		}
		fingerprint := gssh.FingerprintSHA256(p.public)
		if st, e := os.Lstat(path + ".passphrase"); e == nil && st.Mode().IsRegular() && st.Size() <= 65536 {
			p.sidecar, _ = os.ReadFile(path + ".passphrase")
		}
		originalCredential := Credential{Kind: "key", Key: append([]byte(nil), original...), Fingerprint: fingerprint}
		for _, credential := range v.Data.Credentials {
			if credential.Kind != "key" || credential.Fingerprint != fingerprint {
				continue
			}
			if len(credential.Passphrase) > 0 {
				if _, e := gssh.ParseRawPrivateKeyWithPassphrase(original, credential.Passphrase); e == nil {
					originalCredential.Passphrase = append([]byte(nil), credential.Passphrase...)
				}
			}
			if p.raw != nil {
				continue
			}
			raw, e := gssh.ParseRawPrivateKey(credential.Key)
			if e != nil && len(credential.Passphrase) > 0 {
				raw, e = gssh.ParseRawPrivateKeyWithPassphrase(credential.Key, credential.Passphrase)
			}
			if e == nil {
				signer, e := gssh.NewSignerFromKey(raw)
				if e == nil && bytes.Equal(signer.PublicKey().Marshal(), p.public.Marshal()) {
					p.raw = raw
				}
			}
		}
		p.receipt.Original = Digest(originalCredential)
		v.Data.Credentials[p.receipt.Original] = originalCredential
		if p.sidecar != nil {
			backup := Credential{Kind: "password", Password: string(p.sidecar), Fingerprint: "sshm-sidecar-backup:" + Digest([]string{s.DeviceID, path})}
			p.receipt.Recovery = Digest(backup)
			v.Data.Credentials[p.receipt.Recovery] = backup
		}
		if p.raw == nil {
			report.Retained = append(report.Retained, alias+": unlock material unavailable; original retained")
			continue
		}
		// Already encrypted keys without a sidecar need loading, not re-encryption.
		if err == nil || p.sidecar != nil || len(originalCredential.Passphrase) == 0 {
			p.pass = []byte(encoding.EncodeToString(random(32)))
			block, e := gssh.MarshalPrivateKeyWithPassphrase(p.raw, "sshm protected", p.pass)
			if e != nil {
				return report, e
			}
			p.replacement = pem.EncodeToMemory(block)
			replacement := Credential{Kind: "key", Key: append([]byte(nil), p.replacement...), Passphrase: append([]byte(nil), p.pass...), Fingerprint: fingerprint}
			p.receipt.Replacement = Digest(replacement)
			v.Data.Credentials[p.receipt.Replacement] = replacement
			for id, entry := range v.Data.Entries {
				for _, cid := range entry.CredentialIDs {
					if v.Data.Credentials[cid].Kind == "key" && v.Data.Credentials[cid].Fingerprint == fingerprint {
						entry.CredentialIDs = union(entry.CredentialIDs, []string{p.receipt.Replacement})
						v.Data.Entries[id] = entry
						break
					}
				}
			}

		} else {
			p.pass = append([]byte(nil), originalCredential.Passphrase...)
		}
	}
	if err := s.SaveDraft(v, statePath); err != nil {
		return report, err
	}
	if err := s.SyncRetry(ctx, v, statePath); err != nil {
		return report, fmt.Errorf("encrypted backup was not confirmed; no local keys changed: %w", err)
	}
	var receipts []KeyMigration
	for _, p := range plans {
		if p.raw == nil {
			p.receipt.Status = "retained"
			receipts = append(receipts, p.receipt)
			continue
		}
		current, e := os.ReadFile(p.receipt.Path)
		if e != nil || !bytes.Equal(current, p.original) {
			Wipe(current)
			report.Retained = append(report.Retained, p.receipt.Alias+": changed during migration")
			continue
		}
		Wipe(current)
		if e = loadAndProve(p.raw, p.public); e != nil {
			report.Retained = append(report.Retained, p.receipt.Alias+": agent could not prove signing")
			continue
		}
		report.AgentLoaded++
		if len(p.replacement) > 0 {
			if e = WritePrivate(p.receipt.Path, p.replacement); e != nil {
				return report, e
			}
			report.Encrypted++
		}
		// The public key is not secret; recover a missing .pub only after signing proof.
		if _, e = os.Stat(p.receipt.Path + ".pub"); errors.Is(e, os.ErrNotExist) {
			if e = WritePrivate(p.receipt.Path+".pub", gssh.MarshalAuthorizedKey(p.public)); e != nil {
				return report, e
			}
		}
		// The standard resolver must still reach the same signing identity.
		if _, e = sshpkg.CheckKeyPairUsable(p.receipt.Path); e != nil {
			if len(p.replacement) > 0 {
				_ = WritePrivate(p.receipt.Path, p.original)
				report.Encrypted--
			}
			report.Retained = append(report.Retained, p.receipt.Alias+": normal SSH signer verification failed")
			continue
		}
		if p.sidecar != nil {
			current, e = os.ReadFile(p.receipt.Path + ".passphrase")
			same := e == nil && bytes.Equal(current, p.sidecar)
			Wipe(current)
			if same {
				if e = os.Remove(p.receipt.Path + ".passphrase"); e != nil {
					return report, e
				}
				report.RecoveryRemoved++
			}
		}
		p.receipt.Status = "protected-agent-ready"
		receipts = append(receipts, p.receipt)
	}
	data, e := json.MarshalIndent(struct {
		Created time.Time      `json:"created"`
		Items   []KeyMigration `json:"items"`
	}{time.Now().UTC(), receipts}, "", "  ")
	if e != nil {
		return report, e
	}
	if e = WritePrivate(filepath.Join(filepath.Dir(statePath), "key-migration-"+RandomID()+".json"), data); e != nil {
		return report, e
	}
	return report, nil
}
func loadAndProve(raw any, public gssh.PublicKey) error {
	conn, err := sshpkg.DialAgent()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	client := agent.NewClient(conn)
	if err = client.Add(agent.AddedKey{PrivateKey: raw, Comment: "sshm cloud protected key"}); err != nil {
		return err
	}
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		return err
	}
	signature, err := client.Sign(public, challenge)
	if err != nil {
		return err
	}
	return public.Verify(challenge, signature)
}
