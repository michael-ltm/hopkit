package commands

import (
	"bytes"
	"path/filepath"
	"testing"

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
