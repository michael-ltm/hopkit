// Package bootstrap runs an embedded baseline-hardening script on a remote
// server: it installs jq/curl/fail2ban, enables fail2ban, and reports the
// sshd auth configuration. It deliberately does NOT change sshd settings —
// disabling password/root login is an explicit, separate user decision.
package bootstrap

import (
	"context"
	_ "embed"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

//go:embed script.sh
var script string

// Script returns the embedded bootstrap shell script.
func Script() string { return script }

// Result is the parsed outcome of a bootstrap run.
type Result struct {
	Completed bool     `json:"completed"`
	SSHDState []string `json:"sshd_state,omitempty"`
	RawOutput string   `json:"-"`
}

// ParseResult interprets the marker-delimited script output.
func ParseResult(raw string) Result {
	r := Result{RawOutput: raw}
	r.Completed = strings.Contains(raw, "=SSHM-BOOTSTRAP-DONE=")
	inState := false
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "=SSHD-STATE=":
			inState = true
		case strings.HasPrefix(t, "=") && strings.HasSuffix(t, "="):
			inState = false
		case inState && t != "":
			r.SSHDState = append(r.SSHDState, t)
		}
	}
	return r
}

// Run executes the bootstrap script on the remote server via SSH and
// returns the parsed Result. The script is passed as a quoted `sh -c`
// argument, so nothing is written to the remote filesystem.
func Run(ctx context.Context, s *config.Server, options ...sshpkg.BuildOpts) (Result, error) {
	opts := sshpkg.BuildOpts{}
	if len(options) > 0 {
		opts = options[0]
	}
	cli, err := sshpkg.Dial(s, opts)
	if err != nil {
		return Result{}, err
	}
	defer cli.Close()
	res, err := cli.Exec(ctx, "sh -c "+shellQuote(script))
	if err != nil {
		return Result{}, err
	}
	r := ParseResult(res.Stdout)
	if res.Stderr != "" {
		r.RawOutput += "\n=STDERR=\n" + res.Stderr
	}
	return r, nil
}

// shellQuote wraps s in single quotes, escaping any embedded single quote,
// so it survives as one argument to `sh -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
