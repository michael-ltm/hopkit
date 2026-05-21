package commands

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestGenKey_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	keyPath := filepath.Join(dir, "id_test")
	flagConfigPath = cfgPath
	flagJSON = true
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false })

	cmd := newGenKeyCmd()
	cmd.SetArgs([]string{"h", "--path", keyPath})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	var got map[string]string
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, "h", got["alias"])
	require.Contains(t, got["public_key"], "ssh-ed25519")
}
