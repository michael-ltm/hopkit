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
