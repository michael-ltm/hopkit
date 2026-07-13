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
	fields := []struct {
		caseName     string
		name         string
		credential   string
		secretNeedle string
		set          func(*Project, string)
	}{
		{caseName: "PEM local root", name: "local_root", credential: "-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----", secretNeedle: "private-data", set: func(p *Project, v string) { p.LocalRoot = v }},
		{caseName: "URI workspace password", name: "remote_workspace", credential: "ssh://user:workspace-secret@example.com/repo", secretNeedle: "workspace-secret", set: func(p *Project, v string) { p.RemoteWorkspace = v }},
		{caseName: "AWS remote runs", name: "remote_runs", credential: "AKIAIOSFODNN7EXAMPLE", secretNeedle: "AKIAIOSFODNN7EXAMPLE", set: func(p *Project, v string) { p.RemoteRuns = v }},
		{caseName: "Slack artifact path", name: "artifact_path", credential: "/tmp/xoxb-1234567890-abcdefghij", secretNeedle: "xoxb-1234567890-abcdefghij", set: func(p *Project, v string) { p.ArtifactPath = v }},
		{caseName: "JWT local artifact", name: "local_artifact_dir", credential: "eyJhbGciOiJIUzI1NiJ9.payload.signature", secretNeedle: "eyJhbGciOiJIUzI1NiJ9.payload.signature", set: func(p *Project, v string) { p.LocalArtifactDir = v }},
		{caseName: "secret build flag", name: "build_command", credential: "builder --client-secret build-secret", secretNeedle: "build-secret", set: func(p *Project, v string) { p.BuildCommand = v }},
		{caseName: "colon verify token", name: "verify_command", credential: "token: verify-secret", secretNeedle: "verify-secret", set: func(p *Project, v string) { p.VerifyCommand = v }},
		{caseName: "concatenated password", name: "build_command", credential: "DBPASSWORD=db-secret make", secretNeedle: "db-secret", set: func(p *Project, v string) { p.BuildCommand = v }},
		{caseName: "concatenated token", name: "verify_command", credential: "DEPLOYTOKEN=deploy-secret verify", secretNeedle: "deploy-secret", set: func(p *Project, v string) { p.VerifyCommand = v }},
		{caseName: "terminal key", name: "local_root", credential: "SIGNING_KEY=signing-secret", secretNeedle: "signing-secret", set: func(p *Project, v string) { p.LocalRoot = v }},
		{caseName: "mysql short password", name: "build_command", credential: "mysql -uroot -pdb-secret database", secretNeedle: "db-secret", set: func(p *Project, v string) { p.BuildCommand = v }},
		{caseName: "hardcoded env default", name: "verify_command", credential: "TOKEN=${TOKEN:-default-secret} verify", secretNeedle: "default-secret", set: func(p *Project, v string) { p.VerifyCommand = v }},
	}

	for _, field := range fields {
		t.Run(field.caseName, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			cfg := New()
			cfg.Projects["project"] = &Project{
				Server: "prod", RemoteWorkspace: "/srv/app", ArtifactPath: "/srv/app.tgz",
			}
			require.NoError(t, Save(path, cfg))
			before, err := os.ReadFile(path)
			require.NoError(t, err)

			field.set(cfg.Projects["project"], field.credential)
			err = Save(path, cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), field.name)
			require.NotContains(t, err.Error(), field.secretNeedle)
			after, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			require.Equal(t, before, after)
		})
	}
}

func TestSaveAllowsBenignCredentialLikeProjectValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   func(*Project, string)
		get   func(*Project) string
	}{
		{name: "Go parallel flag", value: "go test -parallel=4 ./...", set: func(p *Project, v string) { p.BuildCommand = v }, get: func(p *Project) string { return p.BuildCommand }},
		{name: "port flag", value: "app -port=8080", set: func(p *Project, v string) { p.VerifyCommand = v }, get: func(p *Project) string { return p.VerifyCommand }},
		{name: "profile flag", value: "tool -profile=release", set: func(p *Project, v string) { p.VerifyCommand = v }, get: func(p *Project) string { return p.VerifyCommand }},
		{name: "API key path", value: "API_KEY_PATH=/tmp/api-key build", set: func(p *Project, v string) { p.BuildCommand = v }, get: func(p *Project) string { return p.BuildCommand }},
		{name: "HTTP username", value: "https://alice@example.com/source", set: func(p *Project, v string) { p.LocalRoot = v }, get: func(p *Project) string { return p.LocalRoot }},
		{name: "braced PowerShell env", value: "TOKEN=${env:TOKEN} deploy", set: func(p *Project, v string) { p.BuildCommand = v }, get: func(p *Project) string { return p.BuildCommand }},
		{name: "required POSIX env", value: "TOKEN=${TOKEN:?required} verify", set: func(p *Project, v string) { p.VerifyCommand = v }, get: func(p *Project) string { return p.VerifyCommand }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			cfg := New()
			project := &Project{Server: "prod", RemoteWorkspace: "/srv/app", ArtifactPath: "/srv/app.tgz"}
			tt.set(project, tt.value)
			cfg.Projects["project"] = project

			require.NoError(t, Save(path, cfg))
			loaded, err := Load(path)
			require.NoError(t, err)
			require.Equal(t, tt.value, tt.get(loaded.Projects["project"]))
		})
	}
}

// osIsUnix is a test helper — defined inline to avoid a separate _test.go file.
func osIsUnix() bool {
	return os.PathSeparator == '/'
}
