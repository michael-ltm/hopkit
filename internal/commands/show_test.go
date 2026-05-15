package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestShow_PrintsServerDetail(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{
		Host: "1.2.3.4", Port: 22, User: "ming", Auth: config.AuthKey, KeyPath: "/k",
		Tags: []string{"prod"}, Notes: "primary",
	}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newShowCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, []string{"aliyun"}))
	for _, want := range []string{"aliyun", "1.2.3.4", "ming", "prod", "primary"} {
		require.Contains(t, out.String(), want)
	}
}

func TestShow_ErrorsOnUnknownAlias(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newShowCmd()
	err := cmd.RunE(cmd, []string{"nope"})
	require.Error(t, err)
}
