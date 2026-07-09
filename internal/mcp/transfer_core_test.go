package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopySeekableToAtomicFile_ResumesPartAndRenames(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "artifact.zip")
	part := dst + ".part"
	require.NoError(t, os.WriteFile(part, []byte("hello "), 0o600))

	src := strings.NewReader("hello world")
	sum := sha256.Sum256([]byte("hello world"))
	got, err := copySeekableToAtomicFile(context.Background(), src, int64(src.Len()), dst, transferFileOptions{
		Resume:         true,
		ExpectedSHA256: hex.EncodeToString(sum[:]),
	})

	require.NoError(t, err)
	require.Equal(t, int64(6), got.ResumedFrom)
	require.Equal(t, int64(5), got.BytesCopied)
	require.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	require.FileExists(t, dst)
	require.NoFileExists(t, part)
	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	require.Equal(t, "hello world", string(data))
}

func TestCopySeekableToAtomicFile_LeavesPartOnChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "artifact.zip")
	src := strings.NewReader("wrong content")

	got, err := copySeekableToAtomicFile(context.Background(), src, int64(src.Len()), dst, transferFileOptions{
		ExpectedSHA256: strings.Repeat("0", 64),
	})

	require.Error(t, err)
	require.Empty(t, got.SHA256)
	require.NoFileExists(t, dst)
	require.FileExists(t, dst+".part")
}

func TestTransferManagerTracksBackgroundJobLifecycle(t *testing.T) {
	mgr := newTransferManager()
	id := mgr.start("download", "pc-e5", "remote.zip", "local.zip")
	mgr.update(id, func(job *transferJob) {
		job.BytesTotal = 100
		job.BytesDone = 40
	})
	running, ok := mgr.snapshot(id)
	require.True(t, ok)
	require.Equal(t, "running", running.Status)
	require.Equal(t, int64(40), running.BytesDone)

	mgr.finish(id, transferResult{BytesCopied: 60, BytesTotal: 100, SHA256: strings.Repeat("a", 64)}, nil)
	done, ok := mgr.snapshot(id)
	require.True(t, ok)
	require.Equal(t, "completed", done.Status)
	require.Equal(t, strings.Repeat("a", 64), done.SHA256)
	require.NotEmpty(t, done.FinishedAt)
}
