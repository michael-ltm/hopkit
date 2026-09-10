//go:build darwin || linux

package keystore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAskpassUsesPipeWithoutSecretFiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	secret := "space ' quote \\ and $dollar secret"
	path, cleanup, err := writeAskpass(ctx, secret)
	require.NoError(t, err)
	defer cleanup()
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			require.NoError(t, err)
			require.NotContains(t, string(data), secret)
		} else {
			require.NotZero(t, info.Mode()&os.ModeNamedPipe)
		}
	}
	out, err := exec.CommandContext(ctx, path).Output()
	require.NoError(t, err)
	require.Equal(t, secret+"\n", string(out))
	cleanup()
	_, err = os.Stat(dir)
	require.True(t, os.IsNotExist(err))
}

func TestAskpassCleanupWithoutReaderDoesNotBlock(t *testing.T) {
	path, cleanup, err := writeAskpass(context.Background(), "never consumed")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { cleanup(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup blocked without a FIFO reader")
	}
	_, err = os.Stat(filepath.Dir(path))
	require.True(t, os.IsNotExist(err))
}

func TestAskpassRejectsUnsupportedInputWithoutEcho(t *testing.T) {
	for _, secret := range []string{strings.Repeat("x", 512), "secret\nline", "secret\rline", "secret\x00line"} {
		_, cleanup, err := writeAskpass(context.Background(), secret)
		if cleanup != nil {
			cleanup()
		}
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
	}
}

func TestAskpassDeliversBoundaryValues(t *testing.T) {
	for _, secret := range []string{"", strings.Repeat("x", 511), "密碼 with spaces"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		path, cleanup, err := writeAskpass(ctx, secret)
		require.NoError(t, err)
		out, err := exec.CommandContext(ctx, path).Output()
		cleanup()
		cancel()
		require.NoError(t, err)
		require.Equal(t, secret+"\n", string(out))
	}
}

func TestAskpassCancelledContextCreatesNoHelper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path, cleanup, err := writeAskpass(ctx, "cancelled secret")
	if cleanup != nil {
		cleanup()
	}
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, path)
}

func TestSSHAddRunnerSuppressesEchoedSecretAndRemovesHelper(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "ssh-add")
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s' \"$SSH_ASKPASS\" > \"$1\"\n\"$SSH_ASKPASS\"\nexit 1\n"), 0700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	marker := filepath.Join(dir, "helper-path")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := runSSHAddWithAskpass(ctx, "never-echo-this-secret", marker)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "never-echo-this-secret")
	helper, err := os.ReadFile(marker)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Dir(string(helper)))
	require.True(t, os.IsNotExist(err))
}

func TestSSHAddRunnerCancelsSecondAskpassAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "ssh-add")
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s' \"$SSH_ASKPASS\" > \"$1\"\n\"$SSH_ASKPASS\" >/dev/null\n\"$SSH_ASKPASS\" >/dev/null\n"), 0700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	marker := filepath.Join(dir, "helper-path")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runSSHAddWithAskpass(ctx, "one-shot-secret", marker)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 2*time.Second)
	helper, err := os.ReadFile(marker)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Dir(string(helper)))
	require.True(t, os.IsNotExist(err))
}
