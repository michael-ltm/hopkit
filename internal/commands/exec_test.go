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
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false; flagNoColor = false })

	cmd := newExecCmd()
	cmd.SetArgs([]string{"h"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "command")
}

func TestExec_RegistersAskPasswordFlag(t *testing.T) {
	cmd := newExecCmd()
	flag := cmd.Flags().Lookup("ask-password")
	require.NotNil(t, flag)
	require.Equal(t, "false", flag.DefValue)
}

func TestExec_PasswordAuthRequiresAskPassword(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "example.invalid", User: "u", Auth: config.AuthPassword}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false; flagNoColor = false })

	cmd := newExecCmd()
	cmd.SetArgs([]string{"h", "true"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.EqualError(t, err, "auth=password requires --ask-password")
}

func TestExec_AskPasswordRequiresTTY(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "example.invalid", User: "u", Auth: config.AuthPassword}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false; flagNoColor = false })

	cmd := newExecCmd()
	cmd.SetArgs([]string{"h", "true", "--ask-password"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.EqualError(t, err, "--ask-password requires an interactive terminal; use key or agent auth for automation")
}
