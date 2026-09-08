package config

import (
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestHardwareTOMLRoundTrip(t *testing.T) {
	cfg := New()
	free := uint64(0)
	cfg.Servers["test"] = &Server{Host: "example.invalid", Port: 22, User: "demo", Auth: AuthAgent, Hardware: &inventory.Snapshot{CheckedAt: 123, Status: "ok", MemoryTotal: 32 * 1024 * 1024 * 1024, MemoryAvailable: &free, Disks: []inventory.Disk{{ID: "/dev/sdb", Kind: "disk", Total: 2 * 1024 * 1024 * 1024 * 1024, Free: &free}}}}
	p := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, Save(p, cfg))
	got, e := Load(p)
	require.NoError(t, e)
	require.Equal(t, cfg.Servers["test"].Hardware, got.Servers["test"].Hardware)
}
