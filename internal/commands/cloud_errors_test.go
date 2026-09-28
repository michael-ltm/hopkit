package commands

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

func TestFriendlyCloudErrorPreservesCauseAndLanguage(t *testing.T) {
	old := flagConfigPath
	t.Cleanup(func() { flagConfigPath = old })
	flagConfigPath = filepath.Join(t.TempDir(), "config.toml")
	for _, language := range []string{"en", "zh-CN"} {
		cfg := config.New()
		cfg.UI.Language = language
		require.NoError(t, config.Save(flagConfigPath, cfg))
		original := &cloudsync.APIError{Status: 401, Code: "invalid_login"}
		got := friendlyCloudError(fmt.Errorf("login: %w", original))
		require.ErrorIs(t, got, original)
		var api *cloudsync.APIError
		require.ErrorAs(t, got, &api)
		require.Equal(t, "invalid_login", api.Code)
		if language == "zh-CN" {
			require.Contains(t, got.Error(), "账号不存在或密码错误")
		} else {
			require.Contains(t, got.Error(), "account does not exist or password is incorrect")
		}
		require.Same(t, got, friendlyCloudError(got))
		unlocked := friendlyCloudError(cloudsync.ErrUnlock)
		require.ErrorIs(t, unlocked, cloudsync.ErrUnlock)
		if language == "zh-CN" {
			require.Contains(t, unlocked.Error(), "不是账号密码")
		}
	}
	other := errors.New("unrelated")
	require.Same(t, other, friendlyCloudError(other))
	require.NoError(t, friendlyCloudError(nil))
}

func TestCloudStateErrorsDistinguishMissingAndDamaged(t *testing.T) {
	old := flagConfigPath
	t.Cleanup(func() { flagConfigPath = old })
	flagConfigPath = filepath.Join(t.TempDir(), "config.toml")
	cfg := config.New()
	cfg.UI.Language = "zh-CN"
	require.NoError(t, config.Save(flagConfigPath, cfg))
	_, _, err := cloudState()
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Contains(t, err.Error(), "sshm cloud login")
	require.NoError(t, os.WriteFile(cloudsync.StatePath(flagConfigPath), []byte("broken"), 0600))
	_, _, err = cloudState()
	require.Contains(t, err.Error(), "无法读取")
	require.NotContains(t, err.Error(), "尚未配置")
}

func TestCloudStatusDoesNotHideDamagedAccountAsLocalMode(t *testing.T) {
	old := flagConfigPath
	t.Cleanup(func() { flagConfigPath = old })
	flagConfigPath = filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, config.Save(flagConfigPath, config.New()))
	run := func() (string, error) {
		root := newCloudCmd()
		cmd, _, err := root.Find([]string{"status"})
		require.NoError(t, err)
		var out bytes.Buffer
		cmd.SetOut(&out)
		err = cmd.RunE(cmd, nil)
		return out.String(), err
	}
	out, err := run()
	require.NoError(t, err)
	require.Contains(t, out, "Cloud account not configured")
	require.NoError(t, os.WriteFile(cloudsync.StatePath(flagConfigPath), []byte("broken"), 0600))
	out, err = run()
	require.Error(t, err)
	require.NotContains(t, out, "not configured")
}
