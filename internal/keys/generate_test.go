package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestGenerateED25519_WritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	pub, err := GenerateED25519(path, "test@host")
	require.NoError(t, err)
	require.Contains(t, pub, "ssh-ed25519")
	require.Contains(t, pub, "test@host")

	st, err := os.Stat(path)
	require.NoError(t, err)
	if osIsUnix() {
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	pubData, err := os.ReadFile(path + ".pub")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(pubData), "ssh-ed25519 "))
	require.Contains(t, string(pubData), "test@host", ".pub file should embed comment")

	pubStat, err := os.Stat(path + ".pub")
	require.NoError(t, err)
	if osIsUnix() {
		require.Equal(t, os.FileMode(0o644), pubStat.Mode().Perm())
	}
}

func TestGenerateED25519_RefusesToOverwriteExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	require.NoError(t, os.WriteFile(path, []byte("existing"), 0o600))

	_, err := GenerateED25519(path, "test@host")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestGenerateED25519_StripsNewlinesFromComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_test")
	pub, err := GenerateED25519(path, "good\nmalicious-extra-line")
	require.NoError(t, err)
	// Only one line — comment-injection prevented.
	require.Equal(t, 1, strings.Count(pub, "\n"))
	// Newline was stripped, so there is no injected second line.
	require.NotContains(t, pub, "\nmalicious-extra-line")
	require.Contains(t, pub, "goodmalicious-extra-line")
}

func TestGenerateED25519Encrypted_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_enc")
	pub, err := GenerateED25519Encrypted(path, "enc@host", "s3cr3t-pass")
	require.NoError(t, err)
	require.Contains(t, pub, "ssh-ed25519")

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	// Wrong/empty passphrase must fail; correct one must recover the key.
	_, err = gssh.ParseRawPrivateKey(data)
	require.Error(t, err, "encrypted key must not parse without a passphrase")

	signer, err := gssh.ParsePrivateKeyWithPassphrase(data, []byte("s3cr3t-pass"))
	require.NoError(t, err)
	require.Contains(t, string(gssh.MarshalAuthorizedKey(signer.PublicKey())), "ssh-ed25519")
}

func TestGenerateED25519Encrypted_EmptyPassphraseIsPlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_plain")
	_, err := GenerateED25519Encrypted(path, "plain@host", "")
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = gssh.ParseRawPrivateKey(data) // parses without a passphrase
	require.NoError(t, err)
}

func osIsUnix() bool { return os.PathSeparator == '/' }

func TestRemoveGenerated_RemovesKeyPubAndRecoveryFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_test")
	_, err := GenerateED25519Encrypted(keyPath, "c@sshm", "pw")
	require.NoError(t, err)
	_, err = WriteRecovery(keyPath, "pw")
	require.NoError(t, err)

	require.FileExists(t, keyPath)
	require.FileExists(t, keyPath+".pub")
	require.FileExists(t, keyPath+".passphrase")

	RemoveGenerated(keyPath)

	require.NoFileExists(t, keyPath)
	require.NoFileExists(t, keyPath+".pub")
	require.NoFileExists(t, keyPath+".passphrase")
}

func TestRemoveGenerated_IgnoresMissingFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_missing")
	// None of these files exist; RemoveGenerated must not panic or error.
	require.NotPanics(t, func() { RemoveGenerated(keyPath) })
}

// TestRemoveGenerated_CleansUpAfterFatalWriteRecoveryFailure mirrors the
// scenario a caller (gen-key CLI / gen_key MCP tool) hits on a retry: a
// stale .passphrase file is already present (e.g. left over from a prior
// partial run), so WriteRecovery refuses to overwrite it and returns an
// error. That is a genuinely fatal error occurring *after* the key was
// already written to disk, so the caller must clean up the orphaned key
// files — otherwise a subsequent retry would hit
// GenerateED25519Encrypted's "key already exists" refusal and wedge
// permanently. This exercises that exact fatal-path/cleanup contract at the
// keys layer, since exercising it through the CLI/MCP orchestration would
// require an encrypted key (passphrase != ""), which also drives the real
// keystore.StoreAndLoad call — unsafe to run outside SSHM_KEYSTORE_E2E
// because on macOS that touches the real login keychain.
func TestRemoveGenerated_CleansUpAfterFatalWriteRecoveryFailure(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_test")

	// Simulate the stale recovery file that makes WriteRecovery fail.
	require.NoError(t, os.WriteFile(keyPath+".passphrase", []byte("stale"), 0o600))

	_, err := GenerateED25519Encrypted(keyPath, "c@sshm", "pw")
	require.NoError(t, err)
	require.FileExists(t, keyPath)
	require.FileExists(t, keyPath+".pub")

	_, err = WriteRecovery(keyPath, "pw")
	require.Error(t, err, "WriteRecovery must refuse to overwrite an existing recovery file")

	// Mirror the cleanup callers perform on this fatal path.
	RemoveGenerated(keyPath)

	require.NoFileExists(t, keyPath, "orphaned private key must be removed on retry-wedging failures")
	require.NoFileExists(t, keyPath+".pub", "orphaned public key must be removed on retry-wedging failures")
	require.NoFileExists(t, keyPath+".passphrase", "stale recovery file must be removed so a retry can proceed")

	// A retry now succeeds instead of hitting "key already exists".
	_, err = GenerateED25519Encrypted(keyPath, "c@sshm", "pw2")
	require.NoError(t, err, "retry after cleanup must not be wedged")
}
