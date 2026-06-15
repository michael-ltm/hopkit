package config

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

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
