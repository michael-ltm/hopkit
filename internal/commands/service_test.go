package commands

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestServiceCommandsRegisteredAndStatusSafe(t *testing.T) {
	previous := flagConfigPath
	t.Cleanup(func() { flagConfigPath = previous })
	root := NewRoot()
	root.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "config.toml"), "service", "status"})
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	require.NoError(t, root.Execute())
	var status map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &status))
	require.False(t, status["configured"].(bool))
	require.False(t, status["running"].(bool))
	require.Len(t, status, 6)
	require.Equal(t, "not_started", status["sync"].(map[string]any)["state"])
	service, _, e := root.Find([]string{"service"})
	require.NoError(t, e)
	require.Len(t, service.Commands(), 6)
}
func TestServiceSetupAndUnlockRequireLocalTerminal(t *testing.T) {
	for _, name := range []string{"setup", "unlock"} {
		cmd := newServiceCmd()
		cmd.SetIn(bytes.NewBuffer(nil))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{name})
		require.ErrorContains(t, cmd.Execute(), "local interactive terminal")
	}
}

func TestServiceSetupPassphraseOptInStillRequiresLocalTerminal(t *testing.T) {
	cmd := newServiceCmd()
	cmd.SetIn(bytes.NewBuffer(nil))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"setup", "--ask-passphrases"})
	require.ErrorContains(t, cmd.Execute(), "local interactive terminal")
}
func TestServiceRejectsSecretArguments(t *testing.T) {
	for _, name := range []string{"setup", "unlock", "lock", "run", "status", "install"} {
		cmd := newServiceCmd()
		cmd.SetArgs([]string{name, "secret"})
		require.Error(t, cmd.Execute())
	}
}
