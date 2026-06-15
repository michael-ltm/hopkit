package ssh

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExec_NoClientReturnsError(t *testing.T) {
	c := &Client{}
	_, err := c.Exec(context.Background(), "echo hi")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}

func TestExec_RespectsContextDeadline(t *testing.T) {
	t.Skip("integration — covered by Task 8 against Dockerized sshd")
}

func TestStreamExec_NoClientReturnsError(t *testing.T) {
	c := &Client{}
	_, err := c.StreamExec(context.Background(), "echo hi", io.Discard, io.Discard)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}

func TestCappedBuffer_KeepsBelowCap(t *testing.T) {
	b := newCappedBuffer(16)
	n, err := b.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "hello", b.String())
	require.False(t, b.Truncated())
}

func TestCappedBuffer_TruncatesAboveCap(t *testing.T) {
	const cap = 1024
	b := newCappedBuffer(cap)
	// Write more than the cap, in chunks, to exercise the boundary.
	payload := bytes.Repeat([]byte("x"), cap+500)
	written := 0
	for off := 0; off < len(payload); off += 100 {
		end := off + 100
		if end > len(payload) {
			end = len(payload)
		}
		n, err := b.Write(payload[off:end])
		require.NoError(t, err)
		written += n
	}
	// Writer reports every byte consumed (so the SSH session keeps draining).
	require.Equal(t, len(payload), written)
	// But only cap bytes are retained, and truncation is recorded.
	require.Len(t, b.String(), cap)
	require.True(t, b.Truncated())
}

func TestCappedBuffer_ExactlyCapNotTruncated(t *testing.T) {
	const cap = 256
	b := newCappedBuffer(cap)
	n, err := b.Write(bytes.Repeat([]byte("y"), cap))
	require.NoError(t, err)
	require.Equal(t, cap, n)
	require.Len(t, b.String(), cap)
	require.False(t, b.Truncated())
}
