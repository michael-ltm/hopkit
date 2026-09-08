package cloudsync

import (
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestActivityMergeKeepsLatestWithoutEntryConflict(t *testing.T) {
	cfg := config.New()
	cfg.Servers["demo"] = &config.Server{Host: "example.invalid", User: "test", Port: 22, Auth: "agent"}
	base := NewData()
	_, err := base.Import(cfg, "fixture", false)
	require.NoError(t, err)
	local, remote := NewData(), NewData()
	_, err = local.Import(cfg, "fixture", false)
	require.NoError(t, err)
	_, err = remote.Import(cfg, "fixture", false)
	require.NoError(t, err)
	var id string
	for key := range base.Entries {
		id = key
	}
	local.Activity[id] = Activity{Platform: "linux", LastConnected: 2000, LastSeen: 1000, CheckedAt: 3000}
	remote.Activity[id] = Activity{Platform: "windows", LastConnected: 1000, LastSeen: 4000, CheckedAt: 4000}
	merged, err := Merge(base, local, remote)
	require.NoError(t, err)
	require.Empty(t, merged.Conflicts)
	require.Equal(t, Activity{Platform: "windows", LastConnected: 2000, LastSeen: 4000, CheckedAt: 4000}, merged.Activity[id])
}
func TestProbeActivityDoesNotInventConnection(t *testing.T) {
	cfg := config.New()
	cfg.Servers["demo"] = &config.Server{Host: "example.invalid", User: "test", Port: 22, Auth: "agent", Platform: "linux", LastSeen: time.Now(), LastChecked: time.Now()}
	d := NewData()
	_, err := d.Import(cfg, "fixture", false)
	require.NoError(t, err)
	for _, a := range d.Activity {
		require.Zero(t, a.LastConnected)
		require.Positive(t, a.LastSeen)
		require.Equal(t, "linux", a.Platform)
	}
	require.Len(t, d.Activity, 1)
	require.False(t, d.ImportActivity(cfg))
}
