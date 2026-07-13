package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_ReturnsEmptyConfigWhenFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.toml")
	cfg, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, CurrentVersion, cfg.Version)
	require.Empty(t, cfg.Servers)
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Default = "my-host"
	cfg.Servers["my-host"] = &Server{
		Host: "1.2.3.4", Port: 22, User: "ming", Auth: AuthKey,
		KeyPath: "~/.ssh/id_ed25519", Tags: []string{"prod", "aliyun"},
	}

	require.NoError(t, Save(path, cfg))

	// File exists, mode 0600 on unix.
	st, err := os.Stat(path)
	require.NoError(t, err)
	if mode := st.Mode().Perm(); mode != 0o600 {
		// Windows reports different perm bits — only assert on unix.
		if osIsUnix() {
			t.Fatalf("expected mode 0600 got %o", mode)
		}
	}

	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "my-host", loaded.Default)
	require.Equal(t, "1.2.3.4", loaded.Servers["my-host"].Host)
	require.Equal(t, 22, loaded.Servers["my-host"].Port)
	require.Equal(t, []string{"prod", "aliyun"}, loaded.Servers["my-host"].Tags)
}

func TestLoad_RejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("version = 9999\n[servers]\n"), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported config version")
}

func TestLoadV2InitializesProjectsWithoutImplicitMigration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(p, []byte("version = 2\n[servers]\n"), 0o600))
	cfg, err := Load(p)
	require.NoError(t, err)
	require.Equal(t, 2, cfg.Version)
	require.NotNil(t, cfg.Projects)
}

func TestProjectRoundTripAndSaveUpgrade(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	cfg := New()
	cfg.Version = 2
	cfg.Projects["project_ajie"] = &Project{
		Server: "pc-e5", RemoteWorkspace: `C:\sshm\workspaces\project_ajie`,
		ArtifactPath: `C:\sshm\artifacts\project_ajie\latest\ajie_publish_tool.exe`,
		Shell:        "powershell", BuildCommand: "python build.py onefile",
	}
	require.NoError(t, Save(p, cfg))
	got, err := Load(p)
	require.NoError(t, err)
	require.Equal(t, CurrentVersion, got.Version)
	require.Equal(t, cfg.Projects["project_ajie"], got.Projects["project_ajie"])
}

// osIsUnix is a test helper — defined inline to avoid a separate _test.go file.
func osIsUnix() bool {
	return os.PathSeparator == '/'
}
