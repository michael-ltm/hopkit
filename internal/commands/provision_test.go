package commands

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunProvision_HardenSkippedWhenTestFails(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return errors.New("unreachable") },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	err := runProvision(steps, true /*doHarden*/, nil)
	require.Error(t, err)
	require.Equal(t, []string{"gen", "copy", "test"}, order, "harden must not run after a failed test")
}

func TestRunProvision_FullOrderWhenHealthy(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return nil },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	require.NoError(t, runProvision(steps, true, nil))
	require.Equal(t, []string{"gen", "copy", "test", "harden"}, order)
}

func TestRunProvision_NoHardenFlag(t *testing.T) {
	var order []string
	steps := provisionSteps{
		genKey: func() (string, error) { order = append(order, "gen"); return "pub", nil },
		copyID: func(pw string) error { order = append(order, "copy"); return nil },
		test:   func() error { order = append(order, "test"); return nil },
		harden: func() error { order = append(order, "harden"); return nil },
	}
	require.NoError(t, runProvision(steps, false, nil))
	require.Equal(t, []string{"gen", "copy", "test"}, order)
}

// TestRunProvision_SetsKeyConfirmedOnlyAfterTestPasses proves the gate that
// callers rely on to decide whether to persist key auth to disk: keyConfirmed
// must flip to true only once the connectivity test has actually passed, and
// must stay false if the test step fails (even though gen-key and copy-id
// succeeded and touched the in-memory server struct).
func TestRunProvision_SetsKeyConfirmedOnlyAfterTestPasses(t *testing.T) {
	t.Run("healthy run confirms the key", func(t *testing.T) {
		var confirmed bool
		steps := provisionSteps{
			genKey: func() (string, error) { return "pub", nil },
			copyID: func(pw string) error { return nil },
			test:   func() error { return nil },
			harden: func() error { return nil },
		}
		require.NoError(t, runProvision(steps, false, &confirmed))
		require.True(t, confirmed, "key auth was verified by the test step and must be reported as confirmed")
	})

	t.Run("failed test leaves the key unconfirmed", func(t *testing.T) {
		var confirmed bool
		steps := provisionSteps{
			genKey: func() (string, error) { return "pub", nil },
			copyID: func(pw string) error { return nil },
			test:   func() error { return errors.New("unreachable") },
			harden: func() error { return nil },
		}
		err := runProvision(steps, false, &confirmed)
		require.Error(t, err)
		require.False(t, confirmed, "a failed connectivity test must never mark the key as confirmed")
	})
}

// TestPasswordAuthReportedOff exercises the pure verification helper that
// `hardenDisablePassword` uses to confirm password auth is *actually* off
// after installing the sshd_config.d drop-in and reloading — not just that
// `sshd -t` (syntax check) passed. A passing syntax check says nothing about
// whether the main sshd_config even includes drop-in files (requires
// `Include /etc/ssh/sshd_config.d/*.conf`), so without this check the drop-in
// could be silently inert while the caller reports "password login disabled".
func TestPasswordAuthReportedOff(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"disabled, lowercase", "passwordauthentication no\n", true},
		{"disabled, mixed case as sshd -T sometimes varies", "PasswordAuthentication no\n", true},
		{"disabled, no trailing newline", "passwordauthentication no", true},
		{"still enabled", "passwordauthentication yes\n", false},
		{"empty output — drop-in not honored / grep found nothing", "", false},
		{"whitespace only", "   \n", false},
		{"unexpected value", "passwordauthentication maybe\n", false},
		{"leading/trailing whitespace around a good line", "  passwordauthentication no  \n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, passwordAuthReportedOff(tt.in))
		})
	}
}
