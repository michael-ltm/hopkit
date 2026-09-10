package cloudsync

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/keystore"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type LoadReport struct {
	// Loaded counts distinct identities proved usable, including existing keys.
	Loaded  int      `json:"loaded"`
	Skipped []string `json:"skipped,omitempty"`
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
			raw, err := parseAgentPrivateKey(credential.Key, credential.Passphrase)
			if err != nil && server.KeyPath != "" {
				if recovered, recoveryErr := recoverLocalAgentKey(state, v.Data, entry, server.KeyPath, credential); recoveryErr == nil {
					raw, err = recovered, nil
				}
			}
			if err != nil {
				var missing *gssh.PassphraseMissingError
				if errors.As(err, &missing) && len(credential.Passphrase) == 0 {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%q: encrypted key requires its SSH key passphrase", alias))
				} else {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%q: private key could not be unlocked or parsed", alias))
				}
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

// parseAgentPrivateKey also accepts an unencrypted vault copy that carries a
// passphrase for the matching encrypted local identity.
func parseAgentPrivateKey(key, passphrase []byte) (any, error) {
	raw, err := gssh.ParseRawPrivateKey(key)
	var missing *gssh.PassphraseMissingError
	if errors.As(err, &missing) && len(passphrase) > 0 {
		return gssh.ParseRawPrivateKeyWithPassphrase(key, passphrase)
	}
	return raw, err
}

// recoverLocalAgentKey only restores a local identity declared by the selected
// active entry. Ordinary login passwords are never SSH passphrase candidates.
func recoverLocalAgentKey(state *State, data Data, entry Entry, keyPath string, credential Credential) (any, error) {
	unavailable := errors.New("local identity unlock material unavailable")
	path, err := sshpkg.ExpandHome(keyPath)
	if err != nil {
		return nil, unavailable
	}
	path = filepath.Clean(path)
	local, err := os.ReadFile(path)
	if err != nil {
		return nil, unavailable
	}
	defer Wipe(local)
	public, err := publicIdentity(local, path)
	if err != nil {
		return nil, unavailable
	}
	fingerprint := gssh.FingerprintSHA256(public)
	if credential.Fingerprint != "" {
		if credential.Fingerprint != fingerprint {
			return nil, unavailable
		}
	} else {
		declared, err := publicIdentity(credential.Key, "")
		if err != nil || !bytes.Equal(public.Marshal(), declared.Marshal()) {
			return nil, unavailable
		}
	}
	proveIdentity := func(passphrase []byte) (any, error) {
		raw, err := parseAgentPrivateKey(local, passphrase)
		if err != nil {
			return nil, unavailable
		}
		signer, err := gssh.NewSignerFromKey(raw)
		if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
			return nil, unavailable
		}
		return raw, nil
	}
	if raw, err := proveIdentity(credential.Passphrase); err == nil {
		return raw, nil
	}
	for _, id := range entry.CredentialIDs {
		sidecar := data.Credentials[id]
		if sidecar.Kind != "password" || sidecar.Password == "" || !strings.HasPrefix(sidecar.Fingerprint, "sshm-sidecar-backup:") {
			continue
		}
		if raw, err := proveIdentity([]byte(sidecar.Password)); err == nil {
			return raw, nil
		}
	}
	// Historical hardening receipts stored sidecars outside entry references.
	// Their exact device/path marker supplies the binding, after entry and public
	// identity verification above; unrelated backups cannot be tried.
	if state.DeviceID != "" {
		marker := "sshm-sidecar-backup:" + Digest([]string{state.DeviceID, path})
		for _, sidecar := range data.Credentials {
			if sidecar.Kind != "password" || sidecar.Password == "" || sidecar.Fingerprint != marker {
				continue
			}
			if raw, err := proveIdentity([]byte(sidecar.Password)); err == nil {
				return raw, nil
			}
		}
	}
	return nil, unavailable
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
	pub, _, options, rest, err := gssh.ParseAuthorizedKey(data)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || pub == nil {
		return nil, errors.New("public identity unavailable")
	}
	return pub, nil
}
