package commands

import (
	"bytes"
	"encoding/json"
	"os"
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
	cmd.SetArgs([]string{"h", "--path", keyPath, "--no-encrypt"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, "h", got["alias"])
	require.Contains(t, got["public_key"], "ssh-ed25519")
	require.Equal(t, false, got["encrypted"])
}

func TestGenKeyCmd_DefaultIsEncrypted(t *testing.T) {
	// Opt-in only: the real keystore step runs `ssh-add --apple-use-keychain`,
	// which would pollute the developer's real login keychain. Routine
	// `go test ./...` and CI skip this; run with SSHM_KEYSTORE_E2E=1 manually.
	if os.Getenv("SSHM_KEYSTORE_E2E") == "" {
		t.Skip("set SSHM_KEYSTORE_E2E=1 to exercise the real keystore path")
	}

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

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, "h", got["alias"])
	require.Contains(t, got["public_key"], "ssh-ed25519")
	require.Equal(t, true, got["encrypted"])
}
