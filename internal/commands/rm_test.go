package commands

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRm_RemovesServerWithYes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, reloaded.Servers, "aliyun")
}

func TestRm_ErrorsOnUnknown(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	err := cmd.RunE(cmd, []string{"nope"})
	require.Error(t, err)
}

func TestRm_ClearsDefaultWhenRemovedAliasWasDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	cfg.Default = "aliyun"
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "", reloaded.Default)
	require.NotContains(t, reloaded.Servers, "aliyun")
}

func TestRm_InteractiveAbortKeepsServer(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun"})
	cmd.SetIn(strings.NewReader("n\n"))
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "aborted")

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, reloaded.Servers, "aliyun") // still there
}
