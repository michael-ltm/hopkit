package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestExec_RejectsMissingCommand(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "u", Auth: config.AuthKey, KeyPath: "/k"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newExecCmd()
	cmd.SetArgs([]string{"h"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "command")
}
