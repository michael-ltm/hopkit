package config

import "sync"

// mu serializes all config read-modify-write operations within this process.
// mcp-go dispatches tool calls through a worker pool, so Load→mutate→Save
// sequences in the MCP handlers run concurrently; without this lock the last
// Save wins and silently drops the others.
var mu sync.Mutex

// Update atomically loads the config at path, passes it to fn, and — if fn
// returns nil — saves the (mutated) config back to path. The entire sequence
// is serialized against all other Update calls in this process.
//
// If path does not exist, an empty Config at CurrentVersion is passed to fn
// (matching the behaviour of Load for a missing file).
//
// If fn returns a non-nil error, Save is not called and fn's error is
// returned to the caller unchanged.
func Update(path string, fn func(*Config) error) error {
	mu.Lock()
	defer mu.Unlock()

	cfg, err := Load(path)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return Save(path, cfg)
}
