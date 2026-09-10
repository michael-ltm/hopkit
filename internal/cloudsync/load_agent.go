package cloudsync

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type LoadReport struct {
	// Loaded counts distinct identities proved usable, including existing keys.
	Loaded  int
	Skipped []string
}

// LoadMatchingKeysIntoAgent uses only this unlocked vault and explicit owner.
// It writes public identity mappings, never private keys or unlock material.
// Existing Agent identities retain their constraints; newly added keys expire
// after 12 hours. A later successful sync may load an identity after it expires.
func LoadMatchingKeysIntoAgent(state *State, v *Vault, cfg *config.Config, configPath string) (LoadReport, error) {
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
	proved := map[string]bool{}
	agentReady := false
	for _, alias := range aliases {
		server := cfg.Servers[alias]
		if server == nil || (server.Auth != config.AuthKey && server.Auth != config.AuthCloud && server.Auth != config.AuthAgent) {
			continue
		}
		entry, ok := matchingAgentEntry(v.Data, server, owner)
		if !ok {
			continue
		}
		var publics []gssh.PublicKey
		seen := map[string]bool{}
		for _, id := range entry.CredentialIDs {
			credential := v.Data.Credentials[id]
			if credential.Kind != "key" {
				continue
			}
			raw, err := gssh.ParseRawPrivateKey(credential.Key)
			var missing *gssh.PassphraseMissingError
			if errors.As(err, &missing) {
				if len(credential.Passphrase) == 0 {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%q: encrypted key requires its SSH key passphrase", alias))
					continue
				}
				raw, err = gssh.ParseRawPrivateKeyWithPassphrase(credential.Key, credential.Passphrase)
			}
			if err != nil {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: private key could not be unlocked or parsed", alias))
				continue
			}
			signer, err := gssh.NewSignerFromKey(raw)
			if err != nil {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: unsupported signing key", alias))
				continue
			}
			public := signer.PublicKey()
			fingerprint := gssh.FingerprintSHA256(public)
			if credential.Fingerprint != "" && credential.Fingerprint != fingerprint {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: private key public identity mismatch", alias))
				continue
			}
			if seen[fingerprint] {
				continue
			}
			if !agentReady {
				if err := keystore.EnsureAgent(); err != nil {
					return report, errors.New("local SSH Agent is unavailable")
				}
				agentReady = true
			}
			if err := loadTimedAndProve(raw, public); err != nil {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%q: SSH Agent could not load or prove signing", alias))
				continue
			}
			if !proved[fingerprint] {
				report.Loaded++
				proved[fingerprint] = true
			}
			seen[fingerprint] = true
			publics = append(publics, public)
		}
		if len(publics) > 0 {
			if err := sshpkg.StoreLocalAgentIdentities(configPath, server, publics); err != nil {
				return report, fmt.Errorf("%q: could not store local public identities: %w", alias, err)
			}
		}
	}
	return report, nil
}

func matchingAgentEntry(data Data, server *config.Server, owner string) (Entry, bool) {
	if server.CloudVault != "" && server.CloudVault != owner {
		return Entry{}, false
	}
	active := func(id string) bool { _, conflicted := data.Conflicts[id]; return !data.Deleted[id] && !conflicted }
	matches := func(entry Entry) bool {
		local := cleanServer(*server)
		// The route is independent of whether the local client describes its
		// signer as a file, an Agent identity, or a cloud inventory marker.
		local.Auth = entry.Server.Auth
		return EntryID(local) == EntryID(cleanServer(entry.Server))
	}
	if server.CloudEntry != "" {
		entry, exists := data.Entries[server.CloudEntry]
		return entry, exists && server.CloudVault == owner && active(entry.ID) && matches(entry)
	}
	// Never guess a cloud marker's owner or bind by a reusable display alias.
	if server.Auth == config.AuthCloud {
		return Entry{}, false
	}
	var found Entry
	count := 0
	for id, entry := range data.Entries {
		if active(id) && matches(entry) {
			found = entry
			count++
		}
	}
	return found, count == 1
}

func loadTimedAndProve(raw any, public gssh.PublicKey) error {
	conn, err := sshpkg.DialAgent()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		return err
	}
	exists := false
	for _, key := range keys {
		if bytes.Equal(key.Blob, public.Marshal()) {
			exists = true
			break
		}
	}
	if !exists {
		if err := client.Add(agent.AddedKey{PrivateKey: raw, Comment: "sshm cloud local identity", LifetimeSecs: 12 * 60 * 60}); err != nil {
			return err
		}
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	signature, err := client.Sign(public, challenge)
	if err != nil {
		return err
	}
	return public.Verify(challenge, signature)
}
