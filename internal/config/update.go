package config

import (
	"fmt"
	"os"
	"sync"
)

// mu serializes all config read-modify-write operations within this process.
// mcp-go dispatches tool calls through a worker pool, so Load→mutate→Save
// sequences in the MCP handlers run concurrently; the sidecar OS lock below
// extends that serialization across separate sshm CLI/MCP processes.
var mu sync.Mutex

// Update atomically loads the config at path, passes it to fn, and — if fn
// returns nil — saves the (mutated) config back to path. The entire sequence
// is serialized against all other Save/Update calls that use this config path,
// including calls from another sshm process.
//
// If path does not exist, an empty Config at CurrentVersion is passed to fn
// (matching the behaviour of Load for a missing file).
//
// If fn returns a non-nil error, Save is not called and fn's error is
// returned to the caller unchanged.
//
// Load deliberately leaves optional project validation to its consumer, so fn
// may repair a hand-edited profile. Save still validates the complete project
// set before replacing the file.
func Update(path string, fn func(*Config) error) error {
	return UpdateWithSource(path, func(cfg *Config, _ []byte) error {
		return fn(cfg)
	})
}

// UpdateWithSource is Update plus the exact config bytes that were decoded.
// It is intended for operations such as cleanup that must create a backup from
// the same locked snapshot they validate and mutate.
func UpdateWithSource(path string, fn func(*Config, []byte) error) error {
	mu.Lock()
	defer mu.Unlock()

	unlock, err := lockConfigFile(path)
	if err != nil {
		return err
	}
	defer unlock()

	source, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}
	cfg := New()
	if exists {
		cfg, err = decodeConfig(source)
		if err != nil {
			return err
		}
	}
	if err := fn(cfg, source); err != nil {
		return err
	}
	return saveUnlockedIfUnchanged(path, cfg, &configSnapshot{data: source, exists: exists})
}
