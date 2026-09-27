//go:build linux

package devicekey

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSecretServiceWrappersDoNotOverwritePriorKey(t *testing.T) {
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	saved := map[string][]byte{}
	runCommand = func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		require.NotContains(t, strings.Join(args, " "), "sensitive-master")
		if name == "systemd-creds" {
			return nil, errors.New("not available")
		}
		ref := args[len(args)-1]
		if args[0] == "store" {
			saved[ref] = append([]byte(nil), input...)
			return nil, nil
		}
		if b, ok := saved[ref]; ok {
			require.Equal(t, "search", args[0])
			require.NotContains(t, args, "--unlock")
			return []byte("secret = " + string(b) + "\n"), nil
		}
		return nil, errors.New("missing")
	}
	id := "sshm-" + strings.Repeat("a", 64)
	s := System{}
	backend, a, e := s.Seal(context.Background(), id, []byte("sensitive-master-one"))
	require.NoError(t, e)
	// A different wrapper for the same scope must use its own keyring item;
	// replacing it must never make previously saved ciphertext unreadable.
	backend2, b, e := s.Seal(context.Background(), id, []byte("sensitive-master-two"))
	require.NoError(t, e)
	require.NotEqual(t, backend, backend2)
	first, e := s.Open(context.Background(), id, backend, a)
	require.NoError(t, e)
	require.Equal(t, "sensitive-master-one", string(first))
	second, e := s.Open(context.Background(), id, backend2, b)
	require.NoError(t, e)
	require.Equal(t, "sensitive-master-two", string(second))
	_, e = s.Open(context.Background(), id+"wrong", backend, a)
	require.Error(t, e)
}
func TestSystemdOpenNeverFallsBackToAnotherDeviceKey(t *testing.T) {
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	calls := 0
	runCommand = func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		calls++
		require.Equal(t, "systemd-creds", name)
		return nil, errors.New("provider error with secret")
	}
	_, e := (System{}).Open(context.Background(), "sshm-"+strings.Repeat("b", 64), "systemd-user", bytes.Repeat([]byte{1}, 48))
	require.ErrorIs(t, e, ErrUnavailable)
	require.NotContains(t, e.Error(), "provider error with secret")
	require.Equal(t, 1, calls)
}

// An expired synchronization attempt does not mean that the user's native
// device key is unavailable or that setup/unlock needs to be repeated.
func TestSystemPreservesCallerContextErrors(t *testing.T) {
	id := "sshm-" + strings.Repeat("c", 64)
	for _, tc := range []struct {
		name     string
		deadline bool
		want     error
	}{
		{name: "canceled", want: context.Canceled},
		{name: "deadline", deadline: true, want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tc.deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			t.Run("open", func(t *testing.T) {
				_, err := (System{}).Open(ctx, id, "systemd-user", []byte("synthetic-ciphertext"))
				require.ErrorIs(t, err, tc.want)
				require.NotErrorIs(t, err, ErrUnavailable)
			})
			t.Run("seal", func(t *testing.T) {
				_, _, err := (System{}).Seal(ctx, id, []byte("synthetic-plaintext"))
				require.ErrorIs(t, err, tc.want)
				require.NotErrorIs(t, err, ErrUnavailable)
			})
		})
	}
}

func TestSystemProviderTimeoutDoesNotTriggerFallbackOrSetupAdvice(t *testing.T) {
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	id := "sshm-" + strings.Repeat("d", 64)
	for _, want := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(want.Error(), func(t *testing.T) {
			calls := 0
			runCommand = func(_ context.Context, _ []byte, name string, _ ...string) ([]byte, error) {
				calls++
				require.Equal(t, "systemd-creds", name, "a timed-out native provider must not create a different keyring item")
				return nil, want
			}
			_, _, err := (System{}).Seal(context.Background(), id, []byte("synthetic-plaintext"))
			require.ErrorIs(t, err, want)
			require.Equal(t, 1, calls)
			_, err = (System{}).Open(context.Background(), id, "systemd-user", []byte("synthetic-ciphertext"))
			require.ErrorIs(t, err, want)
			require.Equal(t, 2, calls)
		})
	}
}

func TestSecretServiceTimeoutDoesNotBecomeSetupAdvice(t *testing.T) {
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	runCommand = func(_ context.Context, _ []byte, name string, _ ...string) ([]byte, error) {
		if name == "systemd-creds" {
			return nil, ErrUnavailable
		}
		return nil, context.DeadlineExceeded
	}
	_, _, err := (System{}).Seal(context.Background(), "sshm-"+strings.Repeat("e", 64), []byte("synthetic-plaintext"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// Native Linux characterization: absent graphical-session variables must not
// force setup or unlock. Ciphertext stays in memory; no user's SSHM files or
// Secret Service entries are read or created by this synthetic round trip.
func TestNativeSystemdProtectionWithoutSessionEnvironment(t *testing.T) {
	if os.Getenv("SSHM_DEVICEKEY_E2E") != "1" {
		t.Skip("opt in to native Linux systemd device protection")
	}
	for _, name := range []string{"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
	id := "sshm-" + strings.Repeat("f", 64)
	value := []byte("synthetic-native-devicekey-roundtrip")
	blob, err := runCommand(context.Background(), value, "systemd-creds", "--user", "--name="+id, "--with-key=host", "--no-ask-password", "encrypt", "-", "-")
	require.NoError(t, err)
	require.NotContains(t, string(blob), string(value))
	opened, err := (System{}).Open(context.Background(), id, "systemd-user", blob)
	require.NoError(t, err)
	require.Equal(t, value, opened)
}
