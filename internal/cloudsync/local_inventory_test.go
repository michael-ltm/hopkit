package cloudsync

import (
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalInventoryEmptyDeviceMergeAndSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	source := config.New()
	source.Servers["production"] = &config.Server{Host: "synthetic.invalid", User: "test", Port: 2222, Auth: config.AuthPassword}
	data := NewData()
	_, err := data.Import(source, "source-device", false)
	require.NoError(t, err)
	var id string
	for k := range data.Entries {
		id = k
	}
	data.Credentials["test-password"] = Credential{Kind: "password", Password: "DO-NOT-PERSIST-SYNTHETIC"}
	entry := data.Entries[id]
	entry.CredentialIDs = []string{"test-password"}
	data.Entries[id] = entry
	data.Activity[id] = Activity{LastConnected: time.Now().Add(-time.Hour).UnixMilli(), Platform: "linux"}
	state := &State{URL: DefaultURL, Username: "synthetic", Base: Snapshot{RootPublic: "root-public"}}
	report, err := PublishInventory(path, state, data)
	require.NoError(t, err)
	require.Equal(t, 1, report.Cloud)
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.Equal(t, id, cfg.Servers["production"].CloudEntry)
	require.Empty(t, cfg.Servers["production"].KeyPath)
	require.Equal(t, "linux", cfg.Servers["production"].Platform)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(b), "DO-NOT-PERSIST")
	later := time.Now()
	require.NoError(t, config.RecordSSHUse(path, "production", cfg.Servers["production"], later))
	_, err = PublishInventory(path, state, data)
	require.NoError(t, err)
	cfg, err = config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	require.True(t, cfg.Servers["production"].LastUsed.Equal(later))
	imported := NewData()
	reportImport, err := imported.Import(cfg, "new-device", true)
	require.NoError(t, err)
	require.Zero(t, reportImport.Added)
	delete(data.Entries, id)
	data.Deleted[id] = true
	_, err = PublishInventory(path, state, data)
	require.NoError(t, err)
	cfg, err = config.Load(path)
	require.NoError(t, err)
	require.Empty(t, cfg.Servers)
}
func TestLocalInventoryPreservesLocalAndSeparatesAliasVariants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.New()
	cfg.Servers["prod"] = &config.Server{Host: "local.invalid", User: "local", Port: 22, Auth: config.AuthKey, KeyPath: "/keep/key"}
	require.NoError(t, config.Save(path, cfg))
	data := NewData()
	for _, host := range []string{"one.invalid", "two.invalid"} {
		source := config.New()
		source.Servers["prod"] = &config.Server{Host: host, User: "user", Port: 22, Auth: config.AuthAgent}
		_, err := data.Import(source, "source-device", false)
		require.NoError(t, err)
	}
	state := &State{URL: DefaultURL, Username: "synthetic"}
	_, err := PublishInventory(path, state, data)
	require.NoError(t, err)
	first, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = PublishInventory(path, state, data)
	require.NoError(t, err)
	second, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))
	cfg, err = config.Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 3)
	require.Equal(t, "/keep/key", cfg.Servers["prod"].KeyPath)
	for alias, server := range cfg.Servers {
		if alias != "prod" {
			require.True(t, strings.HasPrefix(alias, "prod~"))
			require.NotEmpty(t, server.CloudEntry)
		}
	}
}
func TestLocalInventoryConflictDoesNotBecomeConnectable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := NewData()
	source := config.New()
	source.Servers["conflicted"] = &config.Server{Host: "test.invalid", User: "test", Port: 22, Auth: config.AuthAgent}
	_, err := data.Import(source, "source-device", false)
	require.NoError(t, err)
	for id, e := range data.Entries {
		data.Conflicts[id] = Conflict{Local: &e, Remote: &e}
	}
	report, err := PublishInventory(path, &State{}, data)
	require.NoError(t, err)
	require.Equal(t, 1, report.Conflicts)
	require.Zero(t, report.Cloud)
}

func TestCloudDeletionBacksUpBoundNativeRecordsAndPreservesDependencies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.New()
	cfg.Servers["ordinary"] = &config.Server{Host: "normal.invalid", User: "test", Port: 22, Auth: config.AuthKey, KeyPath: "/keep/private-key"}
	cfg.Servers["default"] = &config.Server{Host: "default.invalid", User: "test", Port: 22, Auth: config.AuthAgent}
	cfg.Default = "default"
	require.NoError(t, config.Save(path, cfg))
	data := NewData()
	_, err := data.Import(cfg, "source-device", false)
	require.NoError(t, err)
	state := &State{URL: DefaultURL, Username: "test-account"}
	_, err = PublishInventory(path, state, data)
	require.NoError(t, err)
	for id := range data.Entries {
		data.Remove(id)
	}
	report, err := PublishInventory(path, state, data)
	require.NoError(t, err)
	require.Equal(t, 1, report.Removed)
	require.Equal(t, 1, report.Protected)
	require.NotEmpty(t, report.Backup)
	cfg, err = config.Load(path)
	require.NoError(t, err)
	require.NotContains(t, cfg.Servers, "ordinary")
	require.Contains(t, cfg.Servers, "default")
	backup, err := config.Load(report.Backup)
	require.NoError(t, err)
	require.Equal(t, "/keep/private-key", backup.Servers["ordinary"].KeyPath)
}

func TestPublishRepairsLegacyBindingsAndGeneratedDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	state := &State{URL: DefaultURL, Username: "test-legacy"}
	data := NewData()
	source := config.New()
	source.Servers["peer"] = &config.Server{Host: "example.invalid", Port: 22, User: "ops", Auth: config.AuthAgent}
	_, err := data.Import(source, "source-device", false)
	require.NoError(t, err)
	var entry Entry
	for _, e := range data.Entries {
		entry = e
	}
	legacy := config.New()
	server := entry.Server
	server.Auth = config.AuthCloud
	legacy.Servers["peer"] = &server
	dup := server
	dup.CloudEntry = entry.ID
	dup.CloudVault = InventoryIdentity(state)
	legacy.Servers["peer~"+entry.ID[:8]] = &dup
	require.NoError(t, config.Save(path, legacy))
	report, err := PublishInventory(path, state, data)
	require.NoError(t, err)
	require.Equal(t, 1, report.Removed)
	loaded, err := config.Load(path)
	require.NoError(t, err)
	require.Len(t, loaded.Servers, 1)
	require.Equal(t, entry.ID, loaded.Servers["peer"].CloudEntry)
	// A subsequent old writer cannot discard the independently saved binding.
	server.CloudEntry = ""
	server.CloudVault = ""
	legacy.Servers = map[string]*config.Server{"peer": &server}
	require.NoError(t, config.Save(path, legacy))
	loaded, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, entry.ID, loaded.Servers["peer"].CloudEntry)
	// Changing the endpoint is never accepted as the same cloud identity.
	server.Host = "changed.invalid"
	legacy.Servers["peer"] = &server
	require.NoError(t, config.Save(path, legacy))
	restoreLegacyBindings(legacy, data, InventoryIdentity(state))
	require.Empty(t, legacy.Servers["peer"].CloudEntry)
}
