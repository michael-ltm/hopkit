package cloudsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sort"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	gssh "golang.org/x/crypto/ssh"
)

// ImportProtected imports explicitly configured local connections and their
// device-protected credentials into encrypted vault data. It never publishes
// credentials, writes recovery files, or guesses a foreign cloud association.
// Metadata-only imports never open the device protector. Legacy callers can
// continue using Import for configured files and recovery sidecars.
func (d *Data) ImportProtected(ctx context.Context, cfg *config.Config, device string, includeKeys bool, store *localstore.Store, expectedOwner string) (ImportReport, error) {
	var report ImportReport
	if cfg == nil {
		return report, errors.New("local configuration is required")
	}
	aliases := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		target := cfg.Servers[alias]
		if target == nil || target.CloudEntry != "" || (target.CloudVault != "" && target.CloudVault != expectedOwner) || target.Auth == config.AuthCloud {
			continue
		}
		id := EntryID(cleanServer(*target))
		if d.Deleted[id] {
			report.SkippedDeleted++
			continue
		}
		if _, conflicted := d.Conflicts[id]; conflicted {
			report.Existing++
			continue
		}
		single := config.New()
		single.Servers[alias] = target
		var cs []localstore.Credential
		if includeKeys && store != nil && store.Enabled() {
			var err error
			cs, err = store.Resolve(ctx, target)
			if errors.Is(err, localstore.ErrInactive) {
				report.SkippedDeleted++
				continue
			}
			if err != nil && !errors.Is(err, localstore.ErrNotFound) {
				return report, errors.New("protected local credentials could not be verified; unlock or repair the local store before importing")
			}
		}
		if !includeKeys || len(cs) == 0 {
			legacy, err := d.Import(single, device, includeKeys)
			addImportReport(&report, legacy)
			if err != nil {
				return report, err
			}
			continue
		}
		imported, err := protectedCredentials(target, cs)
		localstore.CloseCredentials(cs)
		if err != nil {
			return report, err
		}
		metadata, err := d.Import(single, device, false)
		addImportReport(&report, metadata)
		if err != nil {
			for _, c := range imported {
				Wipe(c.Key)
				Wipe(c.Passphrase)
			}
			return report, err
		}
		entry := d.Entries[id]
		hasKeys, hasPassword := false, false
		for _, c := range imported {
			cid := Digest(c)
			obsolete := []string{}
			for _, oldID := range entry.CredentialIDs {
				old := d.Credentials[oldID]
				// Replace the legacy locked copy of these exact encrypted key bytes.
				// Other identities, credential variants and conflict references survive.
				if oldID != cid && c.Kind == "key" && old.Kind == "key" && len(old.Passphrase) == 0 && bytes.Equal(old.Key, c.Key) {
					if _, e := gssh.ParsePrivateKey(old.Key); e != nil {
						obsolete = append(obsolete, oldID)
					}
				}
			}
			for _, oldID := range obsolete {
				entry.CredentialIDs = withoutCredential(entry.CredentialIDs, oldID)
			}
			d.Credentials[cid] = c
			entry.CredentialIDs = union(entry.CredentialIDs, []string{cid})
			d.Entries[id] = entry
			for _, oldID := range obsolete {
				d.pruneUnreferencedCredential(oldID)
			}
			if c.Kind == "key" {
				report.Keys++
				hasKeys = true
			} else if c.Kind == "password" {
				hasPassword = true
			}
		}
		if hasKeys && target.Auth == config.AuthAgent {
			report.AgentOnly--
		}
		if hasPassword && target.Auth == config.AuthPassword {
			report.NeedsPasswords--
		}
	}
	// Keep cloud-bound activity observations, which legacy Import handled for
	// the full configuration, while requiring this vault's exact owner binding.
	activityCfg := config.New()
	for alias, target := range cfg.Servers {
		if target == nil || (target.CloudVault != "" && target.CloudVault != expectedOwner) {
			continue
		}
		if target.CloudEntry != "" {
			if expectedOwner == "" {
				continue
			}
			if _, ok := matchingAgentEntry(*d, target, expectedOwner); !ok {
				continue
			}
		}
		activityCfg.Servers[alias] = target
	}
	d.ImportActivity(activityCfg)
	return report, d.Validate()
}

func protectedCredentials(target *config.Server, cs []localstore.Credential) ([]Credential, error) {
	var imported []Credential
	success := false
	defer func() {
		if !success {
			for _, c := range imported {
				Wipe(c.Key)
				Wipe(c.Passphrase)
			}
		}
	}()
	passwords := map[string]bool{}
	for _, c := range cs {
		if target.Auth == config.AuthPassword {
			if len(c.Password) > 0 {
				passwords[string(c.Password)] = true
			}
			continue
		}
		if (target.Auth != config.AuthKey && target.Auth != config.AuthAgent) || len(c.Key) == 0 {
			continue
		}
		signer, err := c.Signer()
		if err != nil {
			return nil, errors.New("protected SSH key identity could not be verified")
		}
		challenge := []byte("sshm protected import identity proof")
		signature, err := signer.Sign(rand.Reader, challenge)
		if err != nil || signer.PublicKey().Verify(challenge, signature) != nil {
			return nil, errors.New("protected SSH key could not prove its signing identity")
		}
		imported = append(imported, Credential{Kind: "key", Key: append([]byte(nil), c.Key...), Passphrase: append([]byte(nil), c.Passphrase...), Fingerprint: gssh.FingerprintSHA256(signer.PublicKey())})
	}
	if len(passwords) > 1 {
		return nil, errors.New("conflicting protected passwords require a local selection before import")
	}
	for password := range passwords {
		imported = append(imported, Credential{Kind: "password", Password: password})
	}
	success = true
	return imported, nil
}

func addImportReport(out *ImportReport, in ImportReport) {
	out.Added += in.Added
	out.Existing += in.Existing
	out.Keys += in.Keys
	out.LockedKeys += in.LockedKeys
	out.AgentOnly += in.AgentOnly
	out.NeedsPasswords += in.NeedsPasswords
	out.SkippedDeleted += in.SkippedDeleted
}
func withoutCredential(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, existing := range ids {
		if existing != id {
			out = append(out, existing)
		}
	}
	return out
}
func (d *Data) pruneUnreferencedCredential(id string) {
	references := func(entry Entry) bool {
		for _, cid := range entry.CredentialIDs {
			if cid == id {
				return true
			}
		}
		return false
	}
	for _, entry := range d.Entries {
		if references(entry) {
			return
		}
	}
	for _, conflict := range d.Conflicts {
		if conflict.Local != nil && references(*conflict.Local) || conflict.Remote != nil && references(*conflict.Remote) {
			return
		}
	}
	old := d.Credentials[id]
	Wipe(old.Key)
	Wipe(old.Passphrase)
	delete(d.Credentials, id)
}
