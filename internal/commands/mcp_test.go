package commands

import (
	"testing"
	"time"

	mcppkg "github.com/michael-ltm/sshm/internal/mcp"
	"github.com/stretchr/testify/require"
)

func TestNewMcpCmd_HasCorrectMetadata(t *testing.T) {
	cmd := newMcpCmd()
	require.Equal(t, "mcp", cmd.Name())
	require.Contains(t, cmd.Short, "MCP")
}

func TestMCPCommandSelectsLocalOrBrowser(t *testing.T) {
	for _, mode := range []string{"local", "browser"} {
		t.Run(mode, func(t *testing.T) {
			started := false
			cmd := newMcpCmdWithRunner(func(_ bool, gotMode string, _ mcppkg.CloudSessionPolicy) error {
				require.Equal(t, mode, gotMode)
				started = true
				return nil
			})
			cmd.SetArgs([]string{"--cloud-auth", mode})
			require.NoError(t, cmd.Execute())
			require.True(t, started)
		})
	}
}

func TestMCPCommandRejectsUnknownAuthAndReadOnlyBrowser(t *testing.T) {
	for _, args := range [][]string{{"--cloud-auth", "unknown"}, {"--cloud-auth", "browser", "--read-only"}} {
		cmd := newMcpCmdWithRunner(func(_ bool, _ string, _ mcppkg.CloudSessionPolicy) error {
			t.Fatal("unsupported authentication mode must not start the server")
			return nil
		})
		cmd.SetArgs(args)
		require.Error(t, cmd.Execute())
	}
}

func TestMCPCommandPassesDefaultAndCustomSessionPolicies(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want mcppkg.CloudSessionPolicy
	}{
		{name: "defaults", want: mcppkg.DefaultCloudSessionPolicy()},
		{name: "custom", args: []string{"--cloud-idle-timeout", "3h", "--cloud-session-max-age", "18h"}, want: mcppkg.CloudSessionPolicy{IdleTimeout: 3 * time.Hour, MaximumAge: 18 * time.Hour}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got mcppkg.CloudSessionPolicy
			cmd := newMcpCmdWithRunner(func(_ bool, mode string, policy mcppkg.CloudSessionPolicy) error {
				require.Equal(t, "local", mode)
				got = policy
				return nil
			})
			cmd.SetArgs(tc.args)

			require.NoError(t, cmd.Execute())
			require.Equal(t, tc.want, got)
		})
	}
}

func TestMCPCommandRejectsUnsafeSessionPoliciesBeforeStarting(t *testing.T) {
	for _, args := range [][]string{
		{"--cloud-idle-timeout", "0s"},
		{"--cloud-session-max-age", "0s"},
		{"--cloud-idle-timeout", "721h"},
		{"--cloud-session-max-age", "721h"},
	} {
		t.Run(args[0]+"="+args[1], func(t *testing.T) {
			started := false
			cmd := newMcpCmdWithRunner(func(_ bool, _ string, _ mcppkg.CloudSessionPolicy) error {
				started = true
				return nil
			})
			cmd.SetArgs(args)

			err := cmd.Execute()
			require.Error(t, err)
			require.False(t, started)
		})
	}
}
