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
