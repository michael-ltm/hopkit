package cloudsync

import (
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDeviceEntryDedupAndRoundTrip(t *testing.T) {
	d := NewData()
	device := Device{ID: "Device_Test_123", Label: "Linux one", Kind: "cli", Platform: "linux"}
	e, err := d.AddDevice(device, "", "first")
	require.NoError(t, err)
	id := e.ID
	require.Equal(t, device.ID, DeviceServerID(e.Server))
	e, err = d.AddDevice(device, "renamed", "second")
	require.NoError(t, err)
	require.Equal(t, id, e.ID)
	require.Len(t, d.Entries, 1)
	require.Equal(t, []string{"renamed"}, e.Aliases)
	require.Empty(t, d.Credentials)
	require.NoError(t, d.Validate())
	require.Equal(t, "second", e.Server.Description)
	legacy := config.New()
	legacy.Servers["legacy"] = &e.Server
	_, err = d.Import(legacy, "another-device", false)
	require.NoError(t, err)
	require.Len(t, d.Entries, 1)
	require.Empty(t, DeviceServerID(config.Server{Host: e.Server.Host, User: "other", Port: 22, Auth: "agent"}))
	t.Log("cross-language identity", id)
}
