package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

// This local index contains no credentials. It preserves the binding to the
// pinned vault when older CLI/agent processes strip unknown TOML fields.
type cloudBinding struct {
	Fingerprint string `json:"fingerprint"`
	Entry       string `json:"entry,omitempty"`
	Vault       string `json:"vault"`
}

func bindingFingerprint(s *Server) string {
	b, _ := json.Marshal(struct {
		Host, User, Auth, Key, Jump, Command, Proxy string
		Port                                        int
		Forwards                                    []string
	}{s.Host, s.User, s.Auth, s.KeyPath, s.ProxyJump, s.ProxyCommand, s.Proxy, s.Port, s.Forwards})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func SaveCloudBindings(path string, cfg *Config) error {
	entries := map[string]cloudBinding{}
	for alias, s := range cfg.Servers {
		if s != nil && s.CloudVault != "" {
			entries[alias] = cloudBinding{bindingFingerprint(s), s.CloudEntry, s.CloudVault}
		}
	}
	return saveLocalJSON(path+".cloud-bindings.json", entries)
}
func applyCloudBindings(path string, cfg *Config) *Config {
	b, e := os.ReadFile(path + ".cloud-bindings.json")
	if e != nil || len(b) > 4<<20 {
		return cfg
	}
	var entries map[string]cloudBinding
	if json.Unmarshal(b, &entries) != nil {
		return cfg
	}
	for alias, entry := range entries {
		s := cfg.Servers[alias]
		// Do not resurrect deleted aliases, move bindings across changed routes, or
		// replace explicit bindings that a newer writer has already stored.
		if s == nil || s.CloudVault != "" || s.CloudEntry != "" || entry.Vault == "" || bindingFingerprint(s) != entry.Fingerprint {
			continue
		}
		s.CloudEntry, s.CloudVault = entry.Entry, entry.Vault
	}
	return cfg
}
