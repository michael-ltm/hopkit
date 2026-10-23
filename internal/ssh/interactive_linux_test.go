//go:build linux

package ssh

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

func TestInteractiveFailureRestoresLocalTTY(t *testing.T) {
	for _, rejected := range []string{"pty-req", "shell", "exec"} {
		t.Run(rejected, func(t *testing.T) {
			master, slave, err := pty.Open()
			require.NoError(t, err)
			defer master.Close()
			defer slave.Close()
			previous := os.Stdin
			os.Stdin = slave
			defer func() { os.Stdin = previous }()
			before, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Reject: rejected})
			client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
			require.NoError(t, err)
			defer client.Close()
			if rejected == "shell" {
				err = client.AttachInteractive()
			} else {
				err = client.AttachInteractiveCommand("passwd")
			}
			require.Error(t, err)
			after, err := term.GetState(int(slave.Fd()))
			require.NoError(t, err)
			require.Equal(t, before, after)
			client.Close()
			fixture.WaitClosed(t)
			if rejected == "pty-req" {
				require.Len(t, fixture.Requests(), 2)
			}
		})
	}
}

func TestInteractiveRemoteExitStopsReadingLocalInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer reader.Close()
	defer writer.Close()
	previous := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = previous }()
	fixture := testutil.NewSSHServer(t, testutil.SSHScenario{})
	client, err := Dial(fixture.Target, BuildOpts{ConfigPath: fixture.Path})
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.AttachInteractive())
	// A leftover stdin goroutine would steal this input after remote exit.
	require.NoError(t, reader.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = writer.Write([]byte("after exit"))
	require.NoError(t, err)
	b := make([]byte, len("after exit"))
	_, err = io.ReadFull(reader, b)
	require.NoError(t, err)
	require.Equal(t, "after exit", string(b))
}
