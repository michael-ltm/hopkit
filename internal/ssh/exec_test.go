package ssh

import (
	"context"
	"testing"
	"time"

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
	_ = time.Millisecond
}
