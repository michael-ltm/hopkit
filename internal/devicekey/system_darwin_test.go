//go:build darwin && cgo

package devicekey

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/devicekey/testdata/keychainfixture"
	"github.com/stretchr/testify/require"
)

// Set differently with -ldflags -X when compiling the replacement test binary.
var nativeKeychainBinaryVariant = "original"

//go:embed testdata/keychainfixture/delete.js
var nativeKeychainCleanupScript string

type nativeKeychainFixture struct {
	Instance string
	Backend  string
	Blob     []byte
}

func TestNativeKeychainBinaryReplacement(t *testing.T) {
	if os.Getenv("SSHM_DEVICEKEY_E2E") != "1" {
		t.Skip("opt in from the owning user's unlocked GUI Keychain session")
	}
	replacement := os.Getenv("SSHM_DEVICEKEY_REPLACEMENT_BINARY")
	require.True(t, filepath.IsAbs(replacement), "provide an independently rebuilt replacement test binary")
	dir := t.TempDir()
	id := "sshm-" + strings.Repeat("a", 64)
	backend, blob, err := (System{}).Seal(context.Background(), id, []byte("synthetic-keychain-upgrade-proof"))
	require.NoError(t, err)
	ref, err := reference(backend, "keychain-host")
	require.NoError(t, err)
	t.Cleanup(func() {
		input, err := json.Marshal(map[string]string{"ref": ref})
		require.NoError(t, err)
		output, err := runCommand(context.Background(), input, "/usr/bin/osascript", "-l", "JavaScript", "-e", nativeKeychainCleanupScript)
		require.NoError(t, err, "the stable creating host must delete only its random test item")
		require.Equal(t, "0", strings.TrimSpace(string(output)))
		t.Log("exact synthetic item cleanup: status 0")
	})
	require.Zero(t, keychainfixture.Operation("policy", ref), "new item must preserve default owner and application policy")
	fixture := filepath.Join(dir, "wrapped.json")
	encoded, err := json.Marshal(nativeKeychainFixture{Instance: id, Backend: backend, Blob: blob})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fixture, encoded, 0600))
	current, err := os.Executable()
	require.NoError(t, err)
	a, err := os.ReadFile(current)
	require.NoError(t, err)
	b, err := os.ReadFile(replacement)
	require.NoError(t, err)
	require.False(t, bytes.Equal(a, b), "replacement must have different executable bytes")
	canonical := filepath.Join(dir, "devicekey-test")
	require.NoError(t, os.WriteFile(canonical, a, 0700))
	read := func() {
		t.Helper()
		cmd := exec.Command(canonical, "-test.run=^TestNativeKeychainReplacementReader$", "-test.v")
		cmd.Env = append(os.Environ(), "SSHM_TEST_KEYCHAIN_ENVELOPE="+fixture)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "fresh process must reopen synthetic wrapper: %s", out)
		t.Log(strings.TrimSpace(string(out)))
	}
	read()
	candidate := canonical + ".new"
	require.NoError(t, os.WriteFile(candidate, b, 0700))
	require.NoError(t, os.Rename(candidate, canonical))
	read()
	_, err = (System{}).Open(context.Background(), id+"wrong", backend, blob)
	require.Error(t, err, "the same user cannot reuse a wrapper for a different SSHM instance")
	corrupt := append([]byte(nil), blob...)
	corrupt[len(corrupt)-1] ^= 1
	_, err = (System{}).Open(context.Background(), id, backend, corrupt)
	require.Error(t, err, "modified ciphertext must remain invalid")
}

func TestNativeKeychainReplacementReader(t *testing.T) {
	path := os.Getenv("SSHM_TEST_KEYCHAIN_ENVELOPE")
	if path == "" {
		t.Skip("subprocess for the synthetic replacement test")
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var fixture nativeKeychainFixture
	require.NoError(t, json.Unmarshal(data, &fixture))
	plain, err := (System{}).Open(context.Background(), fixture.Instance, fixture.Backend, fixture.Blob)
	require.NoError(t, err)
	defer clear(plain)
	require.Equal(t, "synthetic-keychain-upgrade-proof", string(plain))
	fmt.Println("synthetic reader variant:", nativeKeychainBinaryVariant)
}
