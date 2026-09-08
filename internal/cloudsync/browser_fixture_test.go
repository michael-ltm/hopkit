package cloudsync

import (
	"encoding/json"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// This opt-in fixture contains only invented test credentials. It proves that
// the browser implementation reads Go ciphertext and Go reads browser edits.
func TestWriteBrowserFixture(t *testing.T) {
	path := os.Getenv("SSHM_CLOUD_BROWSER_FIXTURE")
	if path == "" {
		t.Skip("browser interop fixture not requested")
	}
	v, _, err := NewVault("browser-interop", []byte("synthetic-browser-unlock-phrase"))
	require.NoError(t, err)
	defer v.Close()
	cfg := config.New()
	cfg.Servers["synthetic-host"] = &config.Server{Host: "synthetic.invalid", User: "test", Port: 22, Auth: config.AuthPassword, Group: "original", Tags: []string{"test"}}
	_, err = v.Data.Import(cfg, "synthetic_device", false)
	require.NoError(t, err)
	entry, err := v.Data.Find("synthetic-host")
	require.NoError(t, err)
	require.NoError(t, v.Data.SetPassword(entry.ID, "synthetic-password-preserved"))
	snap, err := v.Snapshot(0, RandomID())
	require.NoError(t, err)
	snap.Revision = 1
	b, err := json.Marshal(snap)
	require.NoError(t, err)
	require.NoError(t, WritePrivate(path, b))
}
func TestReadBrowserResult(t *testing.T) {
	path := os.Getenv("SSHM_CLOUD_BROWSER_RESULT")
	if path == "" {
		t.Skip("browser interop result not requested")
	}
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var snap Snapshot
	require.NoError(t, json.Unmarshal(b, &snap))
	v, err := Unlock("browser-interop", snap, []byte("synthetic-browser-unlock-phrase"), false)
	require.NoError(t, err)
	defer v.Close()
	entry, err := v.Data.Find("synthetic-host")
	require.NoError(t, err)
	require.Equal(t, "浏览器修改", entry.Server.Group)
	require.Equal(t, []string{"prod", "web"}, entry.Server.Tags)
	require.Equal(t, "synthetic-password-preserved", v.Data.Credentials[entry.CredentialIDs[0]].Password)
}
