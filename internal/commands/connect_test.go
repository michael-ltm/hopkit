package commands

import (
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestConnectExplainsOnlyPTYDenial(t *testing.T) {
	for _, rejected := range []string{"pty-req", "shell", "authentication"} {
		t.Run(rejected, func(t *testing.T) {
			fixture := testutil.NewSSHServer(t, testutil.SSHScenario{Reject: rejected})
			fixture.Target.SSHMCheckedAt = time.Now() // already-discovered inventory
			err := connect("fixture", fixture.Target, false, fixture.Path)
			require.Error(t, err)
			fixture.WaitClosed(t)
			if rejected == "pty-req" {
				require.ErrorContains(t, err, "request pty: ssh: pty-req failed")
				require.ErrorContains(t, err, "authentication succeeded")
				require.ErrorContains(t, err, "sshm exec <alias> --raw-environment <command>")
				require.Len(t, fixture.Requests(), 2, "must not fall back to shell or exec")
			} else {
				require.NotContains(t, err.Error(), "--raw-environment")
				if rejected == "authentication" {
					require.Empty(t, fixture.Requests())
				}
			}
		})
	}
}
