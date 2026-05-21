package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/bootstrap"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestInit_ErrorsOnUnknownAlias(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false })

	cmd := newInitCmd()
	cmd.SetArgs([]string{"nope"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown server")
}

func TestRenderInitResult_ShowsStatusAndSSHDState(t *testing.T) {
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := renderInitResult(cmd, "prod", bootstrap.Result{
		Completed: true,
		SSHDState: []string{"PasswordAuthentication no", "PermitRootLogin no"},
	})
	require.NoError(t, err)
	s := out.String()
	require.Contains(t, s, "bootstrap prod: done")
	require.Contains(t, s, "PasswordAuthentication no")
	require.Contains(t, s, "PermitRootLogin no")
}

func TestRenderInitResult_IncompleteStatus(t *testing.T) {
	cmd := newInitCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, renderInitResult(cmd, "h", bootstrap.Result{Completed: false}))
	require.Contains(t, out.String(), "bootstrap h: incomplete")
}
