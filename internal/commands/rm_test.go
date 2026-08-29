package commands

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRm_RemovesServerWithYes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, reloaded.Servers, "aliyun")
}

func TestRm_ErrorsOnUnknown(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, config.Save(cfgPath, config.New()))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	err := cmd.RunE(cmd, []string{"nope"})
	require.Error(t, err)
}

func TestRm_ClearsDefaultWhenRemovedAliasWasDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	cfg.Default = "aliyun"
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "", reloaded.Default)
	require.NotContains(t, reloaded.Servers, "aliyun")
}

func TestRm_InteractiveAbortKeepsServer(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"aliyun"})
	cmd.SetIn(strings.NewReader("not-aliyun\n"))
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "aborted")

	reloaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Contains(t, reloaded.Servers, "aliyun") // still there
}

func TestRm_RefusesServerReferencedByProject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["builder"] = &config.Server{Host: "1.2.3.4"}
	cfg.Projects["app"] = &config.Project{Server: "builder", RemoteWorkspace: "/srv/app", ArtifactPath: "/srv/app.tgz"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"builder", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "project profiles: app")
	reloaded, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	require.Contains(t, reloaded.Servers, "builder")
}

func TestRm_RefusesServerUsedAsProxyJump(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["gateway"] = &config.Server{Host: "10.0.0.1"}
	cfg.Servers["office"] = &config.Server{Host: "10.0.0.2", ProxyJump: "gateway"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newRmCmd()
	cmd.SetArgs([]string{"gateway", "-y"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "servers using it as ProxyJump: office")

	reloaded, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	require.Contains(t, reloaded.Servers, "gateway")
}

func TestRemoveServerRechecksReferencesInsideAtomicUpdate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["gateway"] = &config.Server{Host: "10.0.0.1"}
	cfg.Servers["zeta"] = &config.Server{Host: "10.0.0.2"}
	cfg.Servers["alpha"] = &config.Server{Host: "10.0.0.3"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	// A preflight snapshot is initially safe, then another writer adds
	// references before deletion. removeServer must validate the locked,
	// current snapshot rather than trusting the stale preflight.
	stale, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, config.CheckServerRemoval(stale, "gateway"))
	require.NoError(t, config.Update(cfgPath, func(latest *config.Config) error {
		latest.Servers["zeta"].ProxyJump = "gateway"
		latest.Servers["alpha"].ProxyJump = "gateway"
		latest.Projects["release"] = &config.Project{
			Server: "gateway", RemoteWorkspace: "/srv/release", ArtifactPath: "/srv/release.tgz",
		}
		return nil
	}))

	err = removeServer("gateway")
	require.Error(t, err)
	require.Contains(t, err.Error(), "project profiles: release")
	require.Contains(t, err.Error(), "servers using it as ProxyJump: alpha, zeta")

	reloaded, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	require.Contains(t, reloaded.Servers, "gateway")
}
