package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testHostKey generates a fresh ed25519 host key and returns its public key.
func testHostKey(t *testing.T) gssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer.PublicKey()
}

// fileContains reports whether path contains a known_hosts line matching addr
// and key (i.e. the host is now pinned).
func fileContains(t *testing.T, path, addr string, key gssh.PublicKey) bool {
	t.Helper()
	matcher, err := knownhosts.New(path)
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	return matcher(addr, remote, key) == nil
}

func writeLine(t *testing.T, path, addr string, key gssh.PublicKey) {
	t.Helper()
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))
}

func TestTOFU_UnknownHostIsPinnedAndAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testHostKey(t)
	cb := tofuHostKeyCallback(path)

	addr := "example.com:22"
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	// Case A: unknown host → accept and pin.
	require.NoError(t, cb(addr, remote, key))
	require.True(t, fileContains(t, path, addr, key), "host should be pinned after first connect")

	// Second call now matches the pinned key.
	require.NoError(t, cb(addr, remote, key))
}

func TestTOFU_KnownMatchingHostAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testHostKey(t)
	addr := "example.com:22"
	writeLine(t, path, addr, key)

	cb := tofuHostKeyCallback(path)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	// Case B: known and matching → accept, no error.
	require.NoError(t, cb(addr, remote, key))
}

func TestTOFU_MismatchedKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	addr := "example.com:22"

	// Pre-write a DIFFERENT key for this host.
	stale := testHostKey(t)
	writeLine(t, path, addr, stale)

	cb := tofuHostKeyCallback(path)
	current := testHostKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	// Case C: present but key differs → reject as possible MITM.
	err := cb(addr, remote, current)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host key mismatch")
	require.Contains(t, err.Error(), "MITM")
}

func TestTOFU_InsecureAcceptsAnyKeyWithoutTouchingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	key := testHostKey(t)

	// Case D: insecure=true → InsecureIgnoreHostKey, accepts and does not
	// create/touch the known_hosts file.
	cb, err := hostKeyCallback(true)
	require.NoError(t, err)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	require.NoError(t, cb("anything:22", remote, key))

	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "insecure mode must not create known_hosts")
}

func TestEnsureKnownHosts_CreatesDirAndFileWithPerms(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, ".ssh", "known_hosts")

	require.NoError(t, ensureKnownHosts(path))

	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	// Idempotent: calling again on existing file is fine.
	require.NoError(t, ensureKnownHosts(path))
}

// TestTOFU_ConcurrentUnknownHostsRace exercises the append mutex: many distinct
// unknown hosts pinned concurrently must all succeed without corrupting the
// file. Run under -race.
func TestTOFU_ConcurrentUnknownHostsRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	cb := tofuHostKeyCallback(path)

	const n = 16
	keys := make([]gssh.PublicKey, n)
	for i := range keys {
		keys[i] = testHostKey(t)
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := net.JoinHostPort(
				net.IPv4(10, 0, byte(i>>8), byte(i)).String(), "22")
			remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
			require.NoError(t, cb(addr, remote, keys[i]))
		}(i)
	}
	wg.Wait()

	// All hosts should now be pinned and match.
	for i := 0; i < n; i++ {
		addr := net.JoinHostPort(
			net.IPv4(10, 0, byte(i>>8), byte(i)).String(), "22")
		require.True(t, fileContains(t, path, addr, keys[i]),
			"host %d should be pinned", i)
	}
}
