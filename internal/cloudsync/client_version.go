package cloudsync

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Capture the launch path before an update renames the mapped executable.
// In particular, Linux /proc/self/exe and Windows can later name the backup.
var installedClientPath = func() string {
	p, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}()
var clientVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+ -]{0,79}$`)

// Read the version from the installed file, never from this process's constant.
// Only launch this application's executable, without a shell, with bounded
// output/time. A missing/broken installation does not become a false version.
func InstalledVersion(ctx context.Context) (string, error) {
	return installedVersionAt(ctx, installedClientPath)
}
func installedVersionAt(ctx context.Context, path string) (string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.Path != "github.com/michael-ltm/sshm/cmd/sshm" {
		return "", errors.New("installed SSHM executable could not be identified")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	var out boundedVersionOutput
	cmd.Stdout = &out
	cmd.Env = append(os.Environ(), "SSHM_NO_UPDATE_CHECK=1")
	if err := cmd.Run(); err != nil {
		return "", errors.New("installed SSHM version could not be read")
	}
	v := strings.TrimSpace(out.String())
	if !clientVersionPattern.MatchString(v) {
		return "", errors.New("invalid installed SSHM version")
	}
	return v, nil
}

type boundedVersionOutput struct{ bytes.Buffer }

func (b *boundedVersionOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 128 {
		return 0, errors.New("oversized version output")
	}
	return b.Buffer.Write(p)
}

// Only account authentication is needed for this public device metadata. It
// does not unlock the vault or change last_seen / live-agent capabilities.
func (s *State) ReportInstalledVersion(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := InstalledVersion(ctx)
	if err != nil {
		return err
	}
	return s.Request(ctx, "POST", "/v1/client-version", map[string]string{"installed_version": v}, nil)
}
