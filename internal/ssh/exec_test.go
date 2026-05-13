package ssh

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExec_NoClientReturnsError(t *testing.T) {
	c := &Client{}
	_, err := c.Exec(context.Background(), "echo hi")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}

func TestExec_RespectsContextDeadline(t *testing.T) {
	t.Skip("integration — covered by Task 8 against Dockerized sshd")
}

func TestStreamExec_NoClientReturnsError(t *testing.T) {
	c := &Client{}
	_, err := c.StreamExec(context.Background(), "echo hi", io.Discard, io.Discard)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}
