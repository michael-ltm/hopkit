//go:build darwin

package devicekey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeychainHostSecretsUseOnlyStdin(t *testing.T) {
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	key := bytes.Repeat([]byte{0xa3}, 32)
	ref := strings.Repeat("b", 32)
	var scripts []string
	runCommand = func(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
		require.Equal(t, "/usr/bin/osascript", name)
		require.Len(t, args, 4)
		require.Equal(t, []string{"-l", "JavaScript", "-e"}, args[:3])
		require.NotContains(t, strings.Join(args, " "), ref)
		require.NotContains(t, strings.Join(args, " "), base64.StdEncoding.EncodeToString(key))
		scripts = append(scripts, args[3])
		var request struct {
			Operation string `json:"operation"`
			Ref       string `json:"ref"`
			Key       []byte `json:"key"`
		}
		require.NoError(t, json.Unmarshal(input, &request))
		require.Equal(t, ref, request.Ref)
		if request.Operation == "create" {
			require.True(t, bytes.Equal(key, request.Key))
			return []byte(`{"status":0}`), nil
		}
		require.Equal(t, "read", request.Operation)
		require.Empty(t, request.Key)
		return json.Marshal(map[string]any{"status": 0, "key": key})
	}
	_, err := keychainHostOperation(context.Background(), ref, key)
	require.NoError(t, err)
	got, err := keychainHostOperation(context.Background(), ref, nil)
	require.NoError(t, err)
	require.True(t, bytes.Equal(key, got))
	require.Equal(t, scripts[0], scripts[1], "the script must stay fixed across requests")
}

func TestKeychainHostRejectsMalformedOrDeniedOutput(t *testing.T) {
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	for _, output := range []string{`{}`, `{"status":-25293}`, `{"status":0}`, `{"status":0,"key":"YQ=="}`, `{"status":0,"key":"invalid"}`, "sensitive provider diagnostic"} {
		runCommand = func(context.Context, []byte, string, ...string) ([]byte, error) { return []byte(output), nil }
		_, err := keychainHostOperation(context.Background(), strings.Repeat("a", 32), nil)
		require.ErrorIs(t, err, ErrUnavailable)
		require.NotContains(t, err.Error(), output)
	}
	runCommand = func(context.Context, []byte, string, ...string) ([]byte, error) { return nil, context.DeadlineExceeded }
	_, err := keychainHostOperation(context.Background(), strings.Repeat("a", 32), nil)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestKeychainHostRejectsInvalidInputBeforeExecution(t *testing.T) {
	original := runCommand
	t.Cleanup(func() { runCommand = original })
	runCommand = func(context.Context, []byte, string, ...string) ([]byte, error) {
		t.Fatal("invalid input must not reach the OS host")
		return nil, nil
	}
	for _, ref := range []string{"", "../other-item", strings.Repeat("a", 31), strings.Repeat("g", 32)} {
		_, err := keychainHostOperation(context.Background(), ref, nil)
		require.ErrorIs(t, err, ErrUnavailable)
	}
	for _, key := range [][]byte{{}, {1}, make([]byte, 33)} {
		_, err := keychainHostOperation(context.Background(), strings.Repeat("a", 32), key)
		require.ErrorIs(t, err, ErrUnavailable)
	}
}
