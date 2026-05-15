package commands

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestLs_PrintsTableForServers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "ming", Auth: config.AuthKey, KeyPath: "/key"}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	flagJSON = false
	flagNoColor = true
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false; flagNoColor = false })

	cmd := newLsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, nil))
	require.Contains(t, out.String(), "aliyun")
	require.Contains(t, out.String(), "1.2.3.4")
}

func TestLs_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["aliyun"] = &config.Server{Host: "1.2.3.4", Port: 22, User: "ming", Auth: config.AuthKey}
	require.NoError(t, config.Save(cfgPath, cfg))
	flagConfigPath = cfgPath
	flagJSON = true
	t.Cleanup(func() { flagConfigPath = ""; flagJSON = false })

	cmd := newLsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.RunE(cmd, nil))

	var got struct {
		Servers map[string]config.Server `json:"servers"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Contains(t, got.Servers, "aliyun")
}
