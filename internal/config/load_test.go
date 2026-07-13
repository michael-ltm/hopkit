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

func TestSaveRejectsProjectCredentialsWithoutModifyingDisk(t *testing.T) {
	const credential = "TOKEN=literal-secret"
	fields := []struct {
		name string
		set  func(*Project, string)
	}{
		{name: "local_root", set: func(p *Project, v string) { p.LocalRoot = v }},
		{name: "remote_workspace", set: func(p *Project, v string) { p.RemoteWorkspace = v }},
		{name: "remote_runs", set: func(p *Project, v string) { p.RemoteRuns = v }},
		{name: "artifact_path", set: func(p *Project, v string) { p.ArtifactPath = v }},
		{name: "local_artifact_dir", set: func(p *Project, v string) { p.LocalArtifactDir = v }},
		{name: "build_command", set: func(p *Project, v string) { p.BuildCommand = v }},
		{name: "verify_command", set: func(p *Project, v string) { p.VerifyCommand = v }},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			cfg := New()
			cfg.Projects["project"] = &Project{
				Server: "prod", RemoteWorkspace: "/srv/app", ArtifactPath: "/srv/app.tgz",
			}
			require.NoError(t, Save(path, cfg))
			before, err := os.ReadFile(path)
			require.NoError(t, err)

			field.set(cfg.Projects["project"], credential)
			err = Save(path, cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), field.name)
			require.NotContains(t, err.Error(), "literal-secret")
			after, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			require.Equal(t, before, after)
		})
	}
}

// osIsUnix is a test helper — defined inline to avoid a separate _test.go file.
func osIsUnix() bool {
	return os.PathSeparator == '/'
}
