package cloudagent

import (
	"context"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAdmissionExpiryDoesNotEndContinuousSession(t *testing.T) {
	for _, continuous := range []bool{false, true} {
		parent, cancel := context.WithCancel(context.Background())
		request := cloudsync.ShellOpen{Expires: time.Now().Add(25 * time.Millisecond).UnixMilli()}
		if continuous {
			request.Lifetime = "connection"
		}
		ctx, stop := terminalContext(parent, request)
		time.Sleep(60 * time.Millisecond)
		if continuous {
			require.NoError(t, ctx.Err())
			_, limited := ctx.Deadline()
			require.False(t, limited)
		} else {
			require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
		}
		cancel()
		require.Error(t, ctx.Err())
		stop()
	}
}
