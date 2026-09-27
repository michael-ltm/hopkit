//go:build !windows

package devicekey

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunCommandPreservesContextErrors(t *testing.T) {
	binary, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("SSHM_TEST_DEVICEKEY_WAIT", "1")
	for _, tc := range []struct {
		name  string
		delay time.Duration
		want  error
	}{
		{name: "already-expired", delay: -time.Second, want: context.DeadlineExceeded},
		{name: "expires-during-command", delay: 50 * time.Millisecond, want: context.DeadlineExceeded},
		{name: "canceled", want: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.delay)
			if tc.want == context.Canceled {
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			_, err := runCommand(ctx, nil, binary, "-test.run=^TestDeviceCommandWaitHelper$")
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, ErrUnavailable)
		})
	}
}

func TestDeviceCommandWaitHelper(t *testing.T) {
	if os.Getenv("SSHM_TEST_DEVICEKEY_WAIT") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}
