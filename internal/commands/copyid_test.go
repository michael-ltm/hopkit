package commands

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunCopyID_InstallsThenVerifies(t *testing.T) {
	var calls []string
	err := runCopyID(copyIDSteps{
		install: func() error {
			calls = append(calls, "install")
			return nil
		},
		verify: func() error {
			calls = append(calls, "verify")
			return nil
		},
	})

	require.NoError(t, err)
	require.Equal(t, []string{"install", "verify"}, calls)
}

func TestRunCopyID_RejectsFalseSuccessWhenKeyAuthFails(t *testing.T) {
	err := runCopyID(copyIDSteps{
		install: func() error { return nil },
		verify:  func() error { return errors.New("permission denied") },
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "public key was written")
	require.Contains(t, err.Error(), "did not accept key authentication")
	require.Contains(t, err.Error(), "PubkeyAuthentication")
}

func TestRunCopyID_DoesNotVerifyAfterInstallFailure(t *testing.T) {
	verified := false
	err := runCopyID(copyIDSteps{
		install: func() error { return errors.New("write failed") },
		verify: func() error {
			verified = true
			return nil
		},
	})

	require.Error(t, err)
	require.False(t, verified)
	require.Contains(t, err.Error(), "install public key")
}
