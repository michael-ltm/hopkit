package cloudsync

import (
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHardwareMergesWithoutServerEditConflict(t *testing.T) {
	cfg := config.New()
	cfg.Servers["test"] = &config.Server{Host: "example.invalid", Port: 22, User: "test", Auth: config.AuthAgent, Hardware: &inventory.Snapshot{CheckedAt: 100, Status: "ok", CPU: "test"}}
	base := NewData()
	_, e := base.Import(cfg, "device-test-123", false)
	require.NoError(t, e)
	var id string
	for key, entry := range base.Entries {
		id = key
		require.Nil(t, entry.Server.Hardware)
	}
	local, remote := NewData(), NewData()
	_, e = local.Import(cfg, "device-test-123", false)
	require.NoError(t, e)
	_, e = remote.Import(cfg, "device-test-123", false)
	require.NoError(t, e)
	local.Hardware["device-test-123"] = &inventory.Snapshot{CheckedAt: 200, Status: "ok", CPU: "new"}
	remote.Hardware["device-test-123"] = &inventory.Snapshot{CheckedAt: 100, Status: "ok", CPU: "old"}
	entry := remote.Entries[id]
	entry.Server.Group = "edited"
	remote.Entries[id] = entry
	out, e := Merge(base, local, remote)
	require.NoError(t, e)
	require.Empty(t, out.Conflicts)
	require.Equal(t, "edited", out.Entries[id].Server.Group)
	require.Equal(t, "new", out.Hardware["device-test-123"].CPU)
	require.NoError(t, out.Validate())
}

func TestDeviceHardwareRemainsEncrypted(t *testing.T) {
	v, _ := fixture(t)
	v.Data.Hardware["device-test-123"] = &inventory.Snapshot{CheckedAt: 123, Status: "ok", CPU: "private-hardware-model", Disks: []inventory.Disk{{ID: "/dev/test", Kind: "volume", Mounts: []string{"/private-mount-name"}}}}
	snap, e := v.Snapshot(0, RandomID())
	require.NoError(t, e)
	require.NotContains(t, snap.Blob, "private-hardware")
	require.NotContains(t, snap.Blob, "private-mount")
	opened, e := Unlock("test-account", snap, []byte("test unlock phrase unique"), false)
	require.NoError(t, e)
	defer opened.Close()
	require.Equal(t, v.Data.Hardware, opened.Data.Hardware)
}
