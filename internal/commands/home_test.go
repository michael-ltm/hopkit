package commands

import (
	"bytes"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func TestHomeShortCommandsAndSettingsPreserveInventory(t *testing.T) {
	oldPath := flagConfigPath
	defer func() { flagConfigPath = oldPath }()
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.New()
	cfg.Servers["keep-me"] = &config.Server{Host: "example.invalid", User: "ops", Port: 22, Auth: "agent"}
	require.NoError(t, config.Save(path, cfg))
	root := NewRoot()
	root.SetArgs([]string{"--config", path, "settings", "--language", "zh-CN"})
	require.NoError(t, root.Execute())
	saved, e := config.Load(path)
	require.NoError(t, e)
	require.Equal(t, "zh-CN", saved.UI.Language)
	require.Contains(t, saved.Servers, "keep-me")
	for _, name := range []string{"login", "logout", "devices", "sync", "settings", "menu", "cloud", "pair", "mcp", "exec"} {
		c, _, e := root.Find([]string{name})
		require.NoError(t, e)
		require.Equal(t, name, c.Name())
	}
	login, _, _ := root.Find([]string{"login"})
	require.NotNil(t, login.Flags().Lookup("username"))
	require.NotNil(t, login.Flags().Lookup("endpoint"))
	root.SetIn(bytes.NewBuffer(nil))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(nil)
	require.NoError(t, root.Execute(), "pipes must get help, never a menu")
}
func TestHomeSummaryDoesNotCountAliasesAsCloudSnapshot(t *testing.T) {
	oldPath := flagConfigPath
	defer func() { flagConfigPath = oldPath }()
	flagConfigPath = filepath.Join(t.TempDir(), "config.toml")
	s := &cloudsync.State{URL: cloudsync.DefaultURL, Username: "test-home", Token: "synthetic", Expires: time.Now().Add(time.Hour).UnixMilli()}
	require.NoError(t, s.Save(cloudsync.StatePath(flagConfigPath)))
	cfg := config.New()
	cfg.Servers["local"] = &config.Server{}
	cfg.Servers["linked"] = &config.Server{CloudVault: cloudsync.InventoryIdentity(s)}
	summary := homeSummary(cfg)
	require.Equal(t, 2, summary.Total)
	require.Equal(t, 1, summary.Local)
	require.Equal(t, 1, summary.Linked)
	require.False(t, summary.CloudKnown)
	require.Equal(t, "test-home", summary.Account)
	s.Token = ""
	require.NoError(t, s.Save(cloudsync.StatePath(flagConfigPath)))
	require.Empty(t, homeSummary(cfg).Account)
}
