package commands

import (
	"bytes"
	"encoding/json"
	gssh "golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS == "windows" {
		t.Skip("automated passphrase-file input is unavailable on Windows")
	}
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
	secretPath := filepath.Join(dir, "managed-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("test user managed key passphrase"), 0600))
	cmd.SetArgs([]string{"h", "--path", keyPath, "--passphrase-file", secretPath})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, "h", got["alias"])
	require.Contains(t, got["public_key"], "ssh-ed25519")
	require.Equal(t, true, got["encrypted"])
}

func TestGenKeyUsesManagedPassphraseWithoutRecoveryCopy(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "127.0.0.1", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	keyPath := filepath.Join(dir, "id_test")
	secretPath := filepath.Join(dir, "managed-secret")
	const secret = "user managed private passphrase"
	require.NoError(t, os.WriteFile(secretPath, []byte(secret+"\n"), 0600))
	oldPath, oldJSON := flagConfigPath, flagJSON
	flagConfigPath, flagJSON = cfgPath, true
	t.Cleanup(func() { flagConfigPath, flagJSON = oldPath, oldJSON })
	// Prevent keychain/agent mutation while exercising real key generation.
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "no-agent"))
	if runtime.GOOS != "linux" {
		t.Skip("Linux test isolates agent via SSH_AUTH_SOCK")
	}
	cmd := newGenKeyCmd()
	cmd.SetArgs([]string{"h", "--path", keyPath, "--passphrase-file", secretPath})
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	require.NoError(t, cmd.Execute())
	require.NoFileExists(t, keyPath+".passphrase")
	require.NotContains(t, out.String()+stderr.String(), secret)
	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	_, err = gssh.ParsePrivateKey(data)
	require.Error(t, err)
	_, err = gssh.ParsePrivateKeyWithPassphrase(data, []byte(secret))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, true, got["encrypted"])
	require.Empty(t, got["recovery_file"])
}

func TestGenKeyRejectsConflictingPassphraseFlagsBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	cmd := newGenKeyCmd()
	cmd.SetArgs([]string{"h", "--path", path, "--no-encrypt", "--passphrase-file", "secret"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "none of the others can be")
	require.NoFileExists(t, path)
}

func TestGenKeyWithoutTerminalDoesNotCreateAnUnrecoverableKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "127.0.0.1", User: "x", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	oldPath, oldJSON, oldStdin := flagConfigPath, flagJSON, os.Stdin
	flagConfigPath, flagJSON = cfgPath, false
	input, err := os.CreateTemp(dir, "input")
	require.NoError(t, err)
	os.Stdin = input
	t.Cleanup(func() { flagConfigPath, flagJSON, os.Stdin = oldPath, oldJSON, oldStdin; input.Close() })
	path := filepath.Join(dir, "key")
	cmd := newGenKeyCmd()
	cmd.SetArgs([]string{"h", "--path", path})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err = cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "interactive terminal")
	require.NoFileExists(t, path)
	require.NoFileExists(t, path+".passphrase")
}
