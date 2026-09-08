//go:build windows

package commands

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// npm-installed Codex / Claude Code commonly expose .cmd shims. Native EXEs
// bypass the shell. For batch shims only fixed arguments and safely quoted
// paths are allowed; unusual shell characters require manual registration.
func integrationProcess(ctx context.Context, binary string, args ...string) (*exec.Cmd, error) {
	ext := strings.ToLower(filepath.Ext(binary))
	if ext != ".cmd" && ext != ".bat" {
		return exec.CommandContext(ctx, binary, args...), nil
	}
	values := append([]string{binary}, args...)
	quoted := make([]string, len(values))
	for i, v := range values {
		if strings.ContainsAny(v, "\"%!\r\n&|<>^") {
			return nil, fmt.Errorf("batch CLI path contains shell characters; register MCP manually")
		}
		quoted[i] = "\"" + v + "\""
	}
	cmd := exec.CommandContext(ctx, "cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd.exe /d /s /c \"" + strings.Join(quoted, " ") + "\""}
	return cmd, nil
}
