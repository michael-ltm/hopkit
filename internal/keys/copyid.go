package keys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// BuildCopyIDCommand returns a single shell command (suitable for SSH Exec)
// that ensures the given public key is present in the remote's
// ~/.ssh/authorized_keys exactly once, with correct permissions.
//
// Panics on empty input or input containing a newline (security guard;
// callers must validate UI input first).
func BuildCopyIDCommand(pubKey string) string {
	// Trim trailing newline so the interpolated heredoc body is exactly
	// one line — the raw-string literal already supplies the EOF terminator.
	pubKey = strings.TrimRight(pubKey, "\n")
	if pubKey == "" {
		panic("BuildCopyIDCommand: empty key")
	}
	if strings.ContainsAny(pubKey, "\n\r") {
		panic("BuildCopyIDCommand: key must not contain newlines")
	}

	// Heredoc with quoted delimiter prevents shell expansion.
	return fmt.Sprintf(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && cat >> ~/.ssh/authorized_keys <<'EOF'
%s
EOF
trap 'rm -f ~/.ssh/authorized_keys.tmp' EXIT && awk '!seen[$0]++' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, pubKey)
}

// CopyID reads the local public key (keyPath + ".pub") and installs it on
// the remote via SSH using the provided password (one-shot, never persisted).
func CopyID(ctx context.Context, srv *config.Server, password, keyPath string) error {
	pubPath := keyPath + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key %s: %w", pubPath, err)
	}
	if len(pubData) == 0 {
		return errors.New("public key file is empty")
	}

	// We connect with auth=password for this one operation, but the
	// server entry on disk stays as auth=key.
	transient := *srv
	transient.Auth = config.AuthPassword
	cli, err := sshpkg.Dial(&transient, sshpkg.BuildOpts{Password: password})
	if err != nil {
		return fmt.Errorf("connect for copy-id: %w", err)
	}
	defer cli.Close()

	key := strings.TrimSpace(string(pubData))
	if strings.ContainsAny(key, "\n\r") {
		return fmt.Errorf("public key file %s contains unexpected line breaks", pubPath)
	}
	cmd := BuildCopyIDCommand(key)
	res, err := cli.Exec(ctx, cmd)
	if err != nil {
		stderr := ""
		if res != nil {
			stderr = res.Stderr
		}
		return fmt.Errorf("install pubkey: %w; remote stderr: %s", err, stderr)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("install pubkey exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
