package mcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestRawExecSkipsDiscoveryAndPreservesRemoteResult(t *testing.T) {
	for _, command := range []string{"docker ps", "docker forbidden", `printf '%s' "two words" --`} {
		t.Run(command, func(t *testing.T) {
			fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Command: "docker ps", Output: "fixture output", Stderr: "TOKEN=fixture-secret"})
			result, err := handleExec(context.Background(), Deps{ConfigPath: fixture.Path, AuditPath: filepath.Join(t.TempDir(), "audit.log")}, map[string]any{"alias": "fixture", "command": command, "reason": "verify restricted raw exec", "raw_environment": true})
			require.NoError(t, err)
			out := result.(map[string]any)
			wantExit := 64
			if command == "docker ps" {
				wantExit = 0
			}
			require.Equal(t, wantExit, out["exit"])
			require.Equal(t, "fixture output", out["stdout"])
			require.Equal(t, "TOKEN=***", out["stderr"])
			fixture.WaitClosed(t)
			requests := fixture.Requests()
			require.Len(t, requests, 2, "no PTY, shell, metadata or environment probes")
			require.Equal(t, "exec", requests[1].Type)
			var payload struct{ Command string }
			require.NoError(t, gssh.Unmarshal(requests[1].Payload, &payload))
			require.Equal(t, command, payload.Command)
		})
	}
}
