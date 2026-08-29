package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateAcrossProcessesKeepsBothMutations(t *testing.T) {
	if os.Getenv("SSHM_CONFIG_LOCK_CHILD") == "1" {
		path := os.Getenv("SSHM_CONFIG_LOCK_PATH")
		alias := os.Getenv("SSHM_CONFIG_LOCK_ALIAS")
		err := Update(path, func(cfg *Config) error {
			// Hold the transaction long enough for the sibling process to
			// contend on the same per-config lock.
			time.Sleep(150 * time.Millisecond)
			cfg.Servers[alias] = &Server{Host: alias, Port: 22, User: "u", Auth: AuthAgent}
			return nil
		})
		require.NoError(t, err)
		return
	}

	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, Save(path, New()))
	commands := make([]*exec.Cmd, 0, 2)
	for _, alias := range []string{"child-a", "child-b"} {
		command := exec.Command(os.Args[0], "-test.run=^TestUpdateAcrossProcessesKeepsBothMutations$")
		command.Env = append(os.Environ(),
			"SSHM_CONFIG_LOCK_CHILD=1",
			"SSHM_CONFIG_LOCK_PATH="+path,
			"SSHM_CONFIG_LOCK_ALIAS="+alias,
		)
		require.NoError(t, command.Start())
		commands = append(commands, command)
	}
	for _, command := range commands {
		require.NoError(t, command.Wait())
	}
	got, err := Load(path)
	require.NoError(t, err)
	require.Contains(t, got.Servers, "child-a")
	require.Contains(t, got.Servers, "child-b")
}

func TestUpdateRejectsNonCooperativeFileChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	before := New()
	before.Servers["original"] = &Server{Host: "original", Port: 22, User: "u", Auth: AuthAgent}
	require.NoError(t, Save(path, before))
	originalBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	externalBytes := []byte("version = 5\n[servers.external]\nhost = \"external\"\nport = 22\nuser = \"u\"\nauth = \"agent\"\n")

	err = UpdateWithSource(path, func(cfg *Config, source []byte) error {
		require.Equal(t, originalBytes, source)
		cfg.Servers["transaction"] = &Server{Host: "transaction", Port: 22, User: "u", Auth: AuthAgent}
		return os.WriteFile(path, externalBytes, 0o600)
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "changed outside sshm")
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, externalBytes, after)
}

// TestUpdate_NoConcurrentLostUpdates launches N goroutines each adding a
// distinct server via Update and asserts all N survive (no lost-update race).
// Run with -race to catch data-race violations too.
func TestUpdate_NoConcurrentLostUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	const N = 50

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			alias := fmt.Sprintf("server%d", i)
			err := Update(path, func(cfg *Config) error {
				cfg.Servers[alias] = &Server{
					Host: "1.2.3.4", Port: 22, User: "u", Auth: AuthAgent,
				}
				return nil
			})
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	cfg, err := Load(path)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, N, "expected all %d servers to be present", N)
	for i := 0; i < N; i++ {
		alias := fmt.Sprintf("server%d", i)
		require.Contains(t, cfg.Servers, alias, "missing server %s", alias)
	}
}

// TestUpdate_AbortOnFnError verifies that when fn returns an error, Save is
// not called and the file is not modified.
func TestUpdate_AbortOnFnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")

	before := New()
	before.Servers["existing"] = &Server{Host: "1.2.3.4"}
	require.NoError(t, Save(path, before))

	err := Update(path, func(cfg *Config) error {
		cfg.Servers["new"] = &Server{Host: "5.6.7.8"}
		return fmt.Errorf("abort this update")
	})
	require.Error(t, err)

	after, err := Load(path)
	require.NoError(t, err)
	require.Contains(t, after.Servers, "existing")
	require.NotContains(t, after.Servers, "new", "aborted update must not persist")
}

// TestUpdate_MissingFileCreatesNewConfig verifies Update behaves the same as
// Load for a missing file (returns an empty config — does not error).
func TestUpdate_MissingFileCreatesNewConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.toml")
	err := Update(path, func(cfg *Config) error {
		cfg.Servers["a"] = &Server{Host: "h"}
		return nil
	})
	require.NoError(t, err)

	cfg, err := Load(path)
	require.NoError(t, err)
	require.Contains(t, cfg.Servers, "a")
}
