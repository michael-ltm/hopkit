package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAddQuick_PersistsServer(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newAddCmd()
	cmd.SetArgs([]string{"--quick", "myhost", "--user", "ubuntu", "--host", "1.2.3.4", "-i", "/tmp/key"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, cfg.Servers, "myhost")
	require.Equal(t, "ubuntu", cfg.Servers["myhost"].User)
	require.Equal(t, config.AuthKey, cfg.Servers["myhost"].Auth)
	require.Equal(t, "/tmp/key", cfg.Servers["myhost"].KeyPath)
}

func TestAddQuick_NoKeyDefaultsToAgent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newAddCmd()
	cmd.SetArgs([]string{"--quick", "agenthost", "--user", "ubuntu", "--host", "1.2.3.4"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, cfg.Servers, "agenthost")
	require.Equal(t, config.AuthAgent, cfg.Servers["agenthost"].Auth)
}
