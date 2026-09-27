//go:build !windows

package devicekey

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// Never include command stderr in an error: credential providers may echo
// inputs. Commands receive secret bytes only on stdin and output is bounded.
var runCommand = func(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	var out limitedBuffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, commandFailure(ctx.Err())
	}
	return out.b.Bytes(), nil
}

// Keep timeouts distinct from unavailable device protection without exposing
// provider diagnostics. A caller may simply have exhausted its overall budget.
func commandFailure(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrUnavailable
	}
}

type limitedBuffer struct{ b bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > 1<<20 {
		return 0, ErrUnavailable
	}
	return b.b.Write(p)
}
