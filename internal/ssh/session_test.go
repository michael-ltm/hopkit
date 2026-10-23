package ssh

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
)

func TestTerminalSessionFailuresPreserveStageAndNeverFallback(t *testing.T) {
	for _, tc := range []struct {
		name, reject, disconnect, stage, code string
		requests                              []string
	}{
		{"session denied", "session", "", "session_open", "session_open_failed", []string{"session"}},
		{"pty denied", "pty-req", "", "pty_request", "pty_denied", []string{"session", "pty-req"}},
		{"pty disconnected", "", "pty-req", "pty_request", "pty_request_failed", []string{"session", "pty-req"}},
		{"shell denied", "shell", "", "shell_start", "shell_start_failed", []string{"session", "pty-req", "shell"}},
	} {
		for _, mode := range []string{"interactive", "stream"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Reject: tc.reject, Disconnect: tc.disconnect})
				client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
				require.NoError(t, err)
				t.Cleanup(func() { client.Close() })
				if mode == "stream" {
					_, err = client.OpenTerminal(context.Background(), 80, 24)
				} else {
					err = client.AttachInteractive()
				}
				var session *SessionError
				require.ErrorAs(t, err, &session)
				require.Equal(t, tc.stage, session.Stage)
				require.Equal(t, tc.code, session.Code)
				require.ErrorIs(t, err, session.Cause)
				require.NotContains(t, err.Error(), "--raw-environment")
				client.Close()
				fixture.WaitClosed(t)
				var requests []string
				for _, r := range fixture.Requests() {
					requests = append(requests, r.Type)
				}
				require.Equal(t, tc.requests, requests)
			})
		}
	}
}

func TestSensitiveInteractiveCommandRequiresPTY(t *testing.T) {
	fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Reject: "pty-req"})
	client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
	require.NoError(t, err)
	defer client.Close()
	err = client.AttachInteractiveCommand("passwd")
	var session *SessionError
	require.ErrorAs(t, err, &session)
	require.Equal(t, "pty_denied", session.Code)
	client.Close()
	fixture.WaitClosed(t)
	require.Len(t, fixture.Requests(), 2)
}

func TestOpenTerminalCancellationPreservesContext(t *testing.T) {
	for _, stage := range []string{"pty-req", "shell"} {
		t.Run(stage, func(t *testing.T) {
			fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Block: stage})
			client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
			require.NoError(t, err)
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.OpenTerminal(ctx, 80, 24); result <- err }()
			require.Eventually(t, func() bool {
				for _, r := range fixture.Requests() {
					if r.Type == stage {
						return true
					}
				}
				return false
			}, time.Second, time.Millisecond)
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
				var session *SessionError
				require.ErrorAs(t, err, &session)
				require.Equal(t, "cancelled", session.Code)
			case <-time.After(time.Second):
				t.Fatal("terminal setup did not cancel")
			}
			fixture.WaitClosed(t)
		})
	}
}

func TestOpenTerminalKeepsPTYInputOutputAndResize(t *testing.T) {
	fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Echo: true})
	client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
	require.NoError(t, err)
	defer client.Close()
	stream, err := client.OpenTerminal(context.Background(), 90, 28)
	require.NoError(t, err)
	defer stream.Close()
	require.NoError(t, stream.Resize(101, 32))
	_, err = stream.Write([]byte("hello\n"))
	require.NoError(t, err)
	b := make([]byte, 6)
	_, err = io.ReadFull(stream, b)
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(b))
	stream.Close()
	fixture.WaitClosed(t)
	requests := fixture.Requests()
	require.Len(t, requests, 4)
	var pty struct {
		Term                      string
		Cols, Rows, Width, Height uint32
		Modes                     string
	}
	require.NoError(t, gssh.Unmarshal(requests[1].Payload, &pty))
	require.Equal(t, "xterm-256color", pty.Term)
	require.EqualValues(t, 90, pty.Cols)
	require.EqualValues(t, 28, pty.Rows)
	require.Equal(t, "shell", requests[2].Type)
	require.Equal(t, "window-change", requests[3].Type)
}

func TestRemoteExitIsNotSessionSetupFailure(t *testing.T) {
	fixture := testutil.NewSSHServer(t, testutil.SSHScenario{ExitCode: 64})
	client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
	require.NoError(t, err)
	defer client.Close()
	stream, err := client.OpenTerminal(context.Background(), 80, 24)
	require.NoError(t, err)
	defer stream.Close()
	_, err = io.ReadAll(stream)
	var exit *gssh.ExitError
	require.ErrorAs(t, err, &exit)
	require.Equal(t, 64, exit.ExitStatus())
	var session *SessionError
	require.False(t, errors.As(err, &session))
}

func TestPTYErrorClassificationIsExact(t *testing.T) {
	for _, tc := range []struct {
		cause error
		code  string
	}{
		{errors.New("ssh: pty-req failed"), "pty_denied"},
		{io.EOF, "pty_request_failed"},
		{errors.New("transport: ssh: pty-req failed"), "pty_request_failed"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "cancelled"},
	} {
		var session *SessionError
		require.ErrorAs(t, sessionError("pty_request", tc.cause), &session)
		require.Equal(t, tc.code, session.Code)
		require.ErrorIs(t, session, tc.cause)
	}
}
