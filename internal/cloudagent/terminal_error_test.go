package cloudagent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
)

func TestSessionFailuresKeepLegacyWireCode(t *testing.T) {
	for _, stage := range []string{"session_open", "pty_request", "stdin_pipe", "shell_start", "terminal_size"} {
		err := &sshpkg.SessionError{Stage: stage, Code: stage + "_failed", Cause: errors.New("private host and command")}
		require.Equal(t, "pty_unavailable", targetError(err))
	}
}

func TestTargetDiagnosticsAreSafeAndCompatible(t *testing.T) {
	for _, tc := range []struct {
		stage, code        string
		requested, granted bool
	}{
		{"terminal_size", "terminal_size_failed", false, false},
		{"session_open", "session_open_failed", false, false},
		{"pty_request", "pty_denied", true, false},
		{"pty_request", "pty_request_failed", true, false},
		{"pty_request", "cancelled", true, false},
		{"pty_request", "timeout", true, false},
		{"stdin_pipe", "stdin_pipe_failed", true, true},
		{"shell_start", "shell_start_failed", true, true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			cause := &sshpkg.SessionError{Stage: tc.stage, Code: tc.code, Cause: errors.New("private host and command")}
			payload := targetErrorPayload(cause)
			raw, err := json.Marshal(payload)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "private")
			var old struct{ Type, Data string }
			require.NoError(t, json.Unmarshal(raw, &old))
			require.Equal(t, "error", old.Type)
			require.Equal(t, "pty_unavailable", old.Data)
			d := payload.Diagnostics
			require.NotNil(t, d)
			require.Equal(t, tc.stage, d.Stage)
			require.Equal(t, tc.code, d.ReasonCode)
			require.True(t, d.SSHAuthenticated)
			require.Equal(t, tc.requested, d.PTYRequested)
			require.Equal(t, tc.granted, d.PTYGranted)
			if tc.code == "pty_denied" {
				require.Equal(t, "explicit_exec", d.SuggestedAction)
			} else {
				require.Empty(t, d.SuggestedAction)
			}
		})
	}
	for _, err := range []error{errors.New("private command"), context.Canceled, &sshpkg.SessionError{Stage: "private host", Code: "private command", Cause: errors.New("private secret")}, &sshpkg.SessionError{Stage: "pty_request", Code: "private command", Cause: errors.New("private secret")}} {
		p := targetErrorPayload(err)
		require.Nil(t, p.Diagnostics)
		b, e := json.Marshal(p)
		require.NoError(t, e)
		require.NotContains(t, string(b), "private")
	}
	p := targetErrorPayload(errors.New("ssh_authentication"))
	require.Equal(t, "ssh_authentication", p.Data)
	require.NotNil(t, p.Diagnostics)
	require.Equal(t, "authentication", p.Diagnostics.Stage)
	require.False(t, p.Diagnostics.SSHAuthenticated)
	require.False(t, p.Diagnostics.PTYRequested)
}
