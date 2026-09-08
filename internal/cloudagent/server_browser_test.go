package cloudagent

import (
	"context"
	"encoding/json"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Run with -timeout 30m; all credentials and the SSH target are synthetic.
func TestBrowserServerTerminalFixture(t *testing.T) {
	path := os.Getenv("SSHM_SERVER_BROWSER_FIXTURE")
	endpoint := os.Getenv("SSHM_BROWSER_QA_ENDPOINT")
	if path == "" || endpoint == "" {
		t.Skip("browser fixture not requested")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	host, port, _ := testSSH(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	user := "qa-" + cloudsync.Digest(cloudsync.RandomID())[:12]
	password := []byte("synthetic-account-password")
	phrase := []byte("synthetic-unlock-phrase")
	v, recovery, e := cloudsync.NewVault(user, phrase)
	require.NoError(t, e)
	defer v.Close()
	s, e := cloudsync.Register(ctx, endpoint, user, "验收连接设备", password, v, recovery)
	require.NoError(t, e)
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		require.NoError(t, s.Request(cleanup, "DELETE", "/v1/account", map[string]string{"password": string(password)}, nil))
	}()
	free := uint64(250 * 1024 * 1024 * 1024)
	h := &inventory.Snapshot{CheckedAt: time.Now().UnixMilli(), Status: "ok", OS: "Test Linux", CPU: "Fixture CPU", Threads: 8, MemoryTotal: 16 * 1024 * 1024 * 1024, Disks: []inventory.Disk{{ID: "/dev/sda", Kind: "disk", Total: 1024 * 1024 * 1024 * 1024}, {ID: "/dev/sda1", Kind: "partition", Parent: "/dev/sda", Total: 900 * 1024 * 1024 * 1024, Free: &free, Mounts: []string{"/synthetic-private-mount"}}}}
	cfg := config.New()
	cfg.Servers["web-ssh-fixture"] = &config.Server{Host: host, Port: port, User: "fixture", Auth: config.AuthPassword, Hardware: h}
	_, e = v.Data.Import(cfg, s.DeviceID, false)
	require.NoError(t, e)
	var id string
	for key := range v.Data.Entries {
		id = key
	}
	require.NoError(t, v.Data.SetPassword(id, "test-secret"))
	v.Data.Hardware[s.DeviceID] = h
	configPath := filepath.Join(home, "config.toml")
	require.NoError(t, config.Save(configPath, cfg))
	statePath := filepath.Join(filepath.Dir(path), "state.json")
	require.NoError(t, s.SaveDraft(v, statePath))
	require.NoError(t, s.Sync(ctx, v, statePath))
	require.NoError(t, s.HeartbeatResources(ctx, "0.8.0-cloud-preview.19", h))
	raw, e := json.Marshal(map[string]any{"username": user, "password": string(password), "phrase": string(phrase), "target": id, "device": s.DeviceID})
	require.NoError(t, e)
	require.NoError(t, cloudsync.WritePrivate(path, raw))
	done := make(chan error, 1)
	go func() { done <- ServeTargets(ctx, s, v, configPath) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			<-done
			return
		case err := <-done:
			require.NoError(t, err)
			return
		case <-tick.C:
			if _, e := os.Stat(path + ".stop"); e == nil {
				cancel()
				<-done
				return
			}
		}
	}
}
