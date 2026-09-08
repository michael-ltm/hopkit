package commands

import (
	"context"
	"encoding/json"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in fixture exercises the real command executor against a disposable
// account and local configuration. No real SSH hosts, keys or sessions are used.
func TestBrowserJobFixture(t *testing.T) {
	path, endpoint := os.Getenv("SSHM_JOB_QA_FIXTURE"), os.Getenv("SSHM_JOB_QA_ENDPOINT")
	if path == "" || endpoint == "" {
		t.Skip("browser job fixture not requested")
	}
	oldConfig, oldVersion := flagConfigPath, Version
	defer func() { flagConfigPath = oldConfig; Version = oldVersion }()
	flagConfigPath = filepath.Join(filepath.Dir(path), "config.toml")
	Version = "0.8.0-cloud-preview.16"
	cfg := config.New()
	for _, a := range []string{"delete-one", "delete-two", "keep-one"} {
		cfg.Servers[a] = &config.Server{Host: a + ".example.invalid", Port: 22, User: "test", Auth: config.AuthPassword, Group: "验收"}
	}
	require.NoError(t, config.Save(configPath(), cfg))
	original, e := os.ReadFile(configPath())
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	user := "qa-jobs-" + cloudsync.RandomID()[:8]
	for i, c := range user {
		if c >= 'A' && c <= 'Z' {
			b := []byte(user)
			b[i] = byte(c + 32)
			user = string(b)
		}
	}
	v, recovery, e := cloudsync.NewVault(user, []byte("synthetic-unlock-phrase"))
	require.NoError(t, e)
	defer v.Close()
	s, e := cloudsync.Register(ctx, endpoint, user, "任务验收设备", []byte("synthetic-account-password"), v, recovery)
	require.NoError(t, e)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		require.NoError(t, s.Request(cleanup, "DELETE", "/v1/account", map[string]string{"password": "synthetic-account-password"}, nil))
	}()
	_, e = cloudsync.Login(ctx, endpoint, user, "离线验收设备", []byte("synthetic-account-password"))
	require.NoError(t, e)
	_, e = v.Data.Import(cfg, s.DeviceID, false)
	require.NoError(t, e)
	statePath := cloudsync.StatePath(configPath())
	require.NoError(t, s.SaveDraft(v, statePath))
	require.NoError(t, s.SyncRetry(ctx, v, statePath))
	info, _ := json.Marshal(map[string]string{"username": user, "password": "synthetic-account-password", "phrase": "synthetic-unlock-phrase", "device_id": s.DeviceID})
	require.NoError(t, cloudsync.WritePrivate(path, info))
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- runCloudAgent(ctx, cmd, s, v, false) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case e := <-done:
			require.NoError(t, e)
			return
		case <-ticker.C:
			if _, e := os.Stat(path + ".stop"); e == nil {
				cancel()
				require.NoError(t, <-done)
				after, e := os.ReadFile(configPath())
				require.NoError(t, e)
				require.Equal(t, original, after)
				return
			}
		}
	}
}
