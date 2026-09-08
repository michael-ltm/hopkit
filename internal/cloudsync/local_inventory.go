package cloudsync

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
)

// InventoryIdentity binds local references to an account and pinned vault root.
func InventoryIdentity(s *State) string {
	return Digest([]string{s.URL, s.Username, s.Base.RootPublic})
}

type InventoryReport struct {
	Cloud, Local, Conflicts, Removed, Protected int
	Backup                                      string
}

// PublishInventory exposes connection metadata, never credentials, to ordinary
// local commands. Existing native records and their key paths remain untouched.
func PublishInventory(path string, state *State, data Data) (InventoryReport, error) {
	var report InventoryReport
	if err := data.Validate(); err != nil {
		return report, err
	}
	owner := InventoryIdentity(state)
	var published *config.Config
	err := config.UpdateWithSource(path, func(cfg *config.Config, source []byte) error {
		published = cfg
		restoreLegacyBindings(cfg, data, owner)
		nativeRemovals := []string{}
		refs := map[string]string{}
		native := map[string]bool{}
		for alias, server := range cfg.Servers {
			if server == nil {
				continue
			}
			if server.CloudEntry == "" {
				id := EntryID(cleanServer(*server))
				if server.CloudVault == owner && data.Deleted[id] {
					if len(config.CleanupProtectionReasons(cfg, alias)) == 0 {
						nativeRemovals = append(nativeRemovals, alias)
					} else {
						report.Protected++
					}
					continue
				}
				if _, exists := data.Entries[id]; exists && (server.CloudVault == "" || server.CloudVault == owner) {
					server.CloudVault = owner
				}
				native[id] = true
				continue
			}
			if server.CloudVault != owner {
				continue
			}
			if _, ok := data.Entries[server.CloudEntry]; !ok || data.Deleted[server.CloudEntry] || data.Conflicts[server.CloudEntry].Local != nil || data.Conflicts[server.CloudEntry].Remote != nil {
				// Keep project/default references resolvable as explicit unavailable entries.
				if len(config.CleanupProtectionReasons(cfg, alias)) == 0 {
					delete(cfg.Servers, alias)
					report.Removed++
				} else {
					report.Protected++
				}
				continue
			}
			if previous := refs[server.CloudEntry]; previous == "" || alias < previous {
				refs[server.CloudEntry] = alias
			}
		}

		// A prior sync with stripped bindings may have made generated aliases.
		// Collapse only proven duplicates with generated names; retain aliases
		// referenced by projects, defaults, jump hosts or cleanup protection.
		for alias, server := range cfg.Servers {
			if server == nil || server.CloudEntry == "" || server.CloudVault != owner {
				continue
			}
			canonical := refs[server.CloudEntry]
			entry, exists := data.Entries[server.CloudEntry]
			if !exists || canonical == "" || canonical == alias || !generatedCloudAlias(alias, entry) {
				continue
			}
			if len(config.CleanupProtectionReasons(cfg, alias)) > 0 {
				continue
			}
			if sameCloudRoute(*server, entry.Server) {
				delete(cfg.Servers, alias)
				report.Removed++
			}
		}
		if len(nativeRemovals) > 0 {
			report.Backup = filepath.Join(filepath.Dir(StatePath(path)), "removed-local-"+RandomID()+".toml")
			if err := WritePrivate(report.Backup, source); err != nil {
				return fmt.Errorf("back up deleted local records: %w", err)
			}
			for _, alias := range nativeRemovals {
				delete(cfg.Servers, alias)
				report.Removed++
			}
		}
		ids := make([]string, 0, len(data.Entries))
		for id := range data.Entries {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		report.Conflicts = len(data.Conflicts)
		for _, id := range ids {
			entry := data.Entries[id]
			if _, conflict := data.Conflicts[id]; conflict || data.Deleted[id] {
				continue
			}
			if native[id] {
				report.Local++
				continue
			}
			alias := refs[id]
			if alias == "" {
				aliases := append([]string(nil), entry.Aliases...)
				sort.Strings(aliases)
				alias = strings.TrimSpace(aliases[0])
				if _, used := cfg.Servers[alias]; used {
					alias += "~" + id[:8]
				}
				base := alias
				for n := 2; cfg.Servers[alias] != nil; n++ {
					alias = fmt.Sprintf("%s-%d", base, n)
				}
			}
			server := entry.Server
			server.KeyPath = ""
			server.Auth = config.AuthCloud
			server.CloudEntry, server.CloudVault = id, owner
			a := data.Activity[id]
			if a.LastConnected > 0 {
				server.LastUsed = time.UnixMilli(a.LastConnected)
			}
			if old := cfg.Servers[alias]; old != nil && old.CloudEntry == id && old.LastUsed.After(server.LastUsed) {
				server.LastUsed = old.LastUsed
			}
			if a.LastSeen > 0 {
				server.LastSeen = time.UnixMilli(a.LastSeen)
			}
			if a.CheckedAt > 0 {
				server.LastChecked = time.UnixMilli(a.CheckedAt)
			}
			if a.SSHCheckedAt > 0 {
				server.LastSSHChecked = time.UnixMilli(a.SSHCheckedAt)
			}
			if a.SSHMCheckedAt > 0 {
				server.SSHMCheckedAt = time.UnixMilli(a.SSHMCheckedAt)
			}
			server.LastStatus, server.LastSSHError = a.Status, a.SSHError
			server.Platform, server.Hardware = a.Platform, a.Hardware
			server.SSHMStatus, server.SSHMVersion = a.SSHMStatus, a.SSHMVersion
			cfg.Servers[alias] = &server
			report.Cloud++
		}
		return nil
	})
	if err == nil {
		err = config.SaveCloudBindings(path, published)
	}
	if err == nil {
		err = writeInventorySummary(path, state, data)
	}
	return report, err
}

// Repair only after the caller has unlocked and authenticated the vault. A
// missing binding never permits guessing a credential, route, or account.
func restoreLegacyBindings(cfg *config.Config, data Data, owner string) {
	for alias, server := range cfg.Servers {
		if server == nil || server.Auth != config.AuthCloud || server.CloudEntry != "" || server.CloudVault != "" {
			continue
		}
		candidates := []string{}
		for id, entry := range data.Entries {
			if data.Deleted[id] || !sameCloudRoute(*server, entry.Server) {
				continue
			}
			named := generatedCloudAlias(alias, entry)
			for _, name := range entry.Aliases {
				named = named || alias == name
			}
			if named {
				candidates = append(candidates, id)
			}
		}
		if len(candidates) == 1 {
			server.CloudEntry = candidates[0]
			server.CloudVault = owner
		}
	}
}
func sameCloudRoute(a, b config.Server) bool {
	// AuthCloud is an index marker; the original auth is inside the vault.
	a.Auth = ""
	b.Auth = ""
	return EntryID(a) == EntryID(b)
}
func generatedCloudAlias(alias string, entry Entry) bool {
	for _, name := range entry.Aliases {
		prefix := name + "~" + entry.ID[:8]
		if alias == prefix {
			return true
		}
		if strings.HasPrefix(alias, prefix+"-") {
			suffix := strings.TrimPrefix(alias, prefix+"-")
			if suffix != "" && strings.Trim(suffix, "0123456789") == "" {
				return true
			}
		}
	}
	return false
}
