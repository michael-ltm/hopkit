package commands

import (
	"bytes"
	"encoding/json"
	"testing"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestRawExecSendsOnlyExactCommandWithUncachedMetadata(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		command string
		exit    int
	}{
		{[]string{"docker", "ps"}, "docker ps", 0},
		{[]string{"printf '%s' \"two words\" --"}, "printf '%s' \"two words\" --", 0},
		{[]string{"docker", "ps"}, "docker ps", 64},
	} {
		t.Run(tc.command, func(t *testing.T) {
			fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Command: tc.command, Output: "fixture output", ExitCode: uint32(tc.exit)})
			previous, previousJSON := flagConfigPath, flagJSON
			flagConfigPath, flagJSON = fixture.Path, true
			t.Cleanup(func() { flagConfigPath, flagJSON = previous, previousJSON })
			cmd := newExecCmd()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetArgs(append([]string{"fixture", "--raw-environment", "--"}, tc.args...))
			require.NoError(t, cmd.Execute())
			var result sshpkg.ExecResult
			require.NoError(t, json.Unmarshal(output.Bytes(), &result))
			require.Equal(t, tc.exit, result.ExitCode)
			require.Equal(t, "fixture output", result.Stdout)
			fixture.WaitClosed(t)
			requests := fixture.Requests()
			require.Len(t, requests, 2, "raw exec must not probe platform, installation or shell")
			require.Equal(t, "exec", requests[1].Type)
			var command struct{ Command string }
			require.NoError(t, gssh.Unmarshal(requests[1].Payload, &command))
			require.Equal(t, tc.command, command.Command)
		})
	}
}
