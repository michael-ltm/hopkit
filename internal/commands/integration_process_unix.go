//go:build !windows

package commands

import (
	"context"
	"os/exec"
)

func integrationProcess(ctx context.Context, binary string, args ...string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, binary, args...), nil
}
