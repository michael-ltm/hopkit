package commands

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestEdit_SetFieldUpdatesValue(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "old"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "user=new", "--set", "port=2222"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	loaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "new", loaded.Servers["h"].User)
	require.Equal(t, 2222, loaded.Servers["h"].Port)
}

func TestEdit_ConnectionIdentityChangeClearsActivityButKeepsCreatedAt(t *testing.T) {
	for _, test := range []struct {
		name string
		set  string
	}{
		{name: "host", set: "host=5.6.7.8"},
		{name: "port", set: "port=2222"},
		{name: "user", set: "user=new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			active := created.Add(time.Hour)
			cfg := config.New()
			cfg.Servers["h"] = &config.Server{
				Host: "1.2.3.4", Port: 22, User: "old", Auth: config.AuthAgent,
				CreatedAt: created, LastUsed: active, LastSeen: active,
				LastChecked: active, LastStatus: config.StatusOnline,
			}
			require.NoError(t, config.Save(cfgPath, cfg))
			flagConfigPath = cfgPath
			t.Cleanup(func() { flagConfigPath = "" })

			cmd := newEditCmd()
			cmd.SetArgs([]string{"h", "--set", test.set})
			cmd.SetOut(&bytes.Buffer{})
			beforeEdit := time.Now().UTC()
			require.NoError(t, cmd.Execute())
			afterEdit := time.Now().UTC()

			loaded, err := config.Load(cfgPath)
			require.NoError(t, err)
			server := loaded.Servers["h"]
			require.Equal(t, created, server.CreatedAt)
			require.False(t, server.IdentityChangedAt.Before(beforeEdit))
			require.False(t, server.IdentityChangedAt.After(afterEdit))
			require.True(t, server.LastUsed.IsZero())
			require.True(t, server.LastSeen.IsZero())
			require.True(t, server.LastChecked.IsZero())
			require.Empty(t, server.LastStatus)
		})
	}
}

func TestEdit_MetadataAndSameIdentityPreserveActivity(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	active := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{
		Host: "1.2.3.4", Port: 22, User: "old", Auth: config.AuthAgent,
		LastUsed: active, LastSeen: active, LastChecked: active, LastStatus: config.StatusOnline,
	}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "host=1.2.3.4", "--set", "description=updated"})
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	loaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	server := loaded.Servers["h"]
	require.Equal(t, active, server.LastUsed)
	require.Equal(t, active, server.LastSeen)
	require.Equal(t, active, server.LastChecked)
	require.Equal(t, config.StatusOnline, server.LastStatus)
	require.True(t, server.IdentityChangedAt.IsZero())
}

func TestEdit_RejectsBadPort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "x"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "port=abc"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "port")
}

func TestEdit_RejectsPortOutOfRange(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "x"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "port=70000"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}

func TestEdit_RejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "x"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "nope=x"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported field")
}

func TestEdit_RejectsMalformedSet(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "x"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h", "--set", "noequals"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected key=value")
}

func TestEdit_RejectsEmptySet(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["h"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "x"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	t.Cleanup(func() { flagConfigPath = "" })

	cmd := newEditCmd()
	cmd.SetArgs([]string{"h"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "--set")
}
