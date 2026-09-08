package cloudagent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Explicitly requested acceptance fixture. All identities and credentials here
// are synthetic. The account is deleted after the stop file or timeout.
func TestBrowserAcceptanceFixture(t *testing.T) {
	path := os.Getenv("SSHM_BROWSER_QA_FIXTURE")
	endpoint := os.Getenv("SSHM_BROWSER_QA_ENDPOINT")
	if path == "" || endpoint == "" {
		t.Skip("interactive browser fixture not requested")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	user := "qa-" + cloudsync.Digest(cloudsync.RandomID())[:12]
	phrase := "synthetic-unlock-phrase"
	password := []byte("synthetic-account-password")
	v, recovery, e := cloudsync.NewVault(user, []byte(phrase))
	require.NoError(t, e)
	defer v.Close()
	state, e := cloudsync.Register(ctx, endpoint, user, "验收设备 · macOS", password, v, recovery)
	require.NoError(t, e)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		require.NoError(t, state.Request(cleanup, "DELETE", "/v1/account", map[string]string{"password": string(password)}, nil))
	}()
	cfg := config.New()
	for i := 0; i < 55; i++ {
		alias := fmt.Sprintf("server-%02d", i)
		cfg.Servers[alias] = &config.Server{Host: fmt.Sprintf("node-%02d.example.invalid", i), User: "deploy", Port: 22, Auth: "password", Group: []string{"生产", "开发", "测试"}[i%3], Tags: []string{"linux", "work", "长标签用于溢出测试"}, Platform: []string{"linux", "macos", "windows"}[i%3], LastUsed: time.Now().Add(-time.Duration(i+1) * time.Hour), LastSeen: time.Now().Add(-time.Duration(i+1) * time.Minute), LastChecked: time.Now(), Description: "用于布局与批量编辑验收的虚构连接"}
	}
	sample := &inventory.Snapshot{CheckedAt: time.Now().UnixMilli(), Status: "ok", OS: "Ubuntu 24.04 LTS", Arch: "x86_64", CPU: "AMD EPYC 7B13", Cores: 8, Threads: 16, MemoryTotal: 32 * 1024 * 1024 * 1024, Disks: []inventory.Disk{{ID: "/dev/nvme0n1", Kind: "disk", Total: 1024 * 1024 * 1024 * 1024}, {ID: "/dev/sdb", Kind: "disk", Total: 2 * 1024 * 1024 * 1024 * 1024}, {ID: "/dev/nvme0n1p1", Kind: "partition", Parent: "/dev/nvme0n1", Mounts: []string{"/", "/srv/data"}, Total: 900 * 1024 * 1024 * 1024}}}
	v.Data.Hardware[state.DeviceID] = sample
	for i, sv := range cfg.Servers {
		if i != "server-03" {
			sv.Hardware = sample
		}
	}
	_, e = v.Data.Import(cfg, state.DeviceID, false)
	require.NoError(t, e)
	for id := range v.Data.Entries {
		require.NoError(t, v.Data.SetPassword(id, "synthetic-ssh-password"))
	}
	statePath := filepath.Join(filepath.Dir(path), "qa-state.json")
	require.NoError(t, state.SaveDraft(v, statePath))
	require.NoError(t, state.Sync(ctx, v, statePath))
	require.NoError(t, state.HeartbeatResources(ctx, "0.8.0-cloud-preview.19", sample))
	b, e := json.Marshal(map[string]any{"username": user, "password": string(password), "phrase": phrase, "root_public": v.Public(), "device_id": state.DeviceID, "endpoint": endpoint})
	require.NoError(t, e)
	require.NoError(t, cloudsync.WritePrivate(path, b))
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, state, v) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-done:
			require.NoError(t, e)
			return
		case <-ticker.C:
			if _, e := os.Stat(path + ".stop"); e == nil {
				cancel()
				<-done
				return
			}
		}
	}
}

func TestBrowserAcceptanceReadback(t *testing.T) {
	path := os.Getenv("SSHM_BROWSER_QA_READBACK")
	if path == "" {
		t.Skip("browser readback not requested")
	}
	s, e := cloudsync.LoadState(filepath.Join(filepath.Dir(path), "qa-state.json"))
	require.NoError(t, e)
	var snap cloudsync.Snapshot
	require.NoError(t, s.Request(context.Background(), "GET", "/v1/vault", nil, &snap))
	v, e := cloudsync.Unlock(s.Username, snap, []byte("synthetic-unlock-phrase"), false)
	require.NoError(t, e)
	defer v.Close()
	require.Len(t, v.Data.Entries, 55)
	changed := 0
	for _, entry := range v.Data.Entries {
		if entry.Server.Group == "验收分组" {
			changed++
			require.Contains(t, entry.Server.Tags, "reviewed")
		}
		require.Len(t, entry.CredentialIDs, 1)
		require.Equal(t, "synthetic-ssh-password", v.Data.Credentials[entry.CredentialIDs[0]].Password)
	}
	require.Equal(t, 25, changed)
}

// Changes only synthetic fixture metadata while its browser remains unlocked.
func TestBrowserActivityUpdate(t *testing.T) {
	path := os.Getenv("SSHM_BROWSER_QA_ACTIVITY_UPDATE")
	if path == "" {
		t.Skip("interactive browser fixture not requested")
	}
	s, e := cloudsync.LoadState(filepath.Join(filepath.Dir(path), "qa-state.json"))
	require.NoError(t, e)
	var snap cloudsync.Snapshot
	require.NoError(t, s.Request(context.Background(), "GET", "/v1/vault", nil, &snap))
	v, e := cloudsync.Unlock(s.Username, snap, []byte("synthetic-unlock-phrase"), false)
	require.NoError(t, e)
	defer v.Close()
	for id, entry := range v.Data.Entries {
		a := v.Data.Activity[id]
		a.SSHMCheckedAt = time.Now().UnixMilli()
		switch entry.Aliases[0] {
		case "server-00":
			a.SSHMStatus = "installed"
			a.SSHMVersion = "0.8.0-cloud-preview.13"
		case "server-01":
			a.SSHMStatus = "installed"
			a.SSHMVersion = "0.7.0"
		case "server-02":
			a.SSHMStatus = "missing"
			a.SSHMVersion = ""
		default:
			a.SSHMStatus = "unknown"
			a.SSHMVersion = ""
		}
		switch entry.Aliases[0] {
		case "server-00":
			a.LastConnected = 0
			a.SSHCheckedAt = time.Now().UnixMilli()
			a.SSHError = "authentication"
		case "server-01":
			a.SSHCheckedAt = time.Now().UnixMilli()
			a.SSHError = "timeout"
		case "server-02":
			a.Status = "offline"
			a.CheckedAt = time.Now().UnixMilli()
		case "server-03":
			a = cloudsync.Activity{}
		case "server-04":
			a.LastConnected = time.Now().UnixMilli()
		}
		v.Data.Activity[id] = a
	}
	cfg := config.New()
	cfg.Servers["never-connected"] = &config.Server{Host: "never.example.invalid", Port: 22, User: "demo", Auth: "agent", Platform: "windows", LastSSHChecked: time.Now(), LastSSHError: "authentication"}
	_, e = v.Data.Import(cfg, s.DeviceID, false)
	require.NoError(t, e)
	require.NoError(t, s.SaveDraft(v, filepath.Join(filepath.Dir(path), "qa-state.json")))
	require.NoError(t, s.Sync(context.Background(), v, filepath.Join(filepath.Dir(path), "qa-state.json")))
}
