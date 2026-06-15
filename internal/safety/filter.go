// Package safety gates dangerous remote commands, masks sensitive data in
// output, and records an audit trail. It is the lowest new layer in v0.2 —
// it imports only the standard library.
package safety

import (
	"regexp"
	"strings"
)

// dangerousPattern pairs a compiled regex with a human-readable reason.
type dangerousPattern struct {
	re     *regexp.Regexp
	reason string
}

// dangerousPatterns is the built-in deny-list. Patterns match against the
// whitespace-collapsed command string. The list is intentionally
// conservative — it targets unambiguously destructive operations.
var dangerousPatterns = []dangerousPattern{
	{regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|/\*|~/?)(\s|$)`), "recursive delete of a root-level or home path"},
	{regexp.MustCompile(`\bmkfs(\.\w+)?\s`), "filesystem creation (mkfs)"},
	{regexp.MustCompile(`\bdd\s+.*of=/dev/`), "raw write to a device with dd"},
	{regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`), "fork bomb"},
	{regexp.MustCompile(`\bchmod\s+-[a-z]*R[a-z]*\s+0{3,4}\s+/(\s|$)`), "recursive chmod 000 on root"},
	{regexp.MustCompile(`>\s*/dev/(sd|nvme|hd|vd)\w*`), "redirect to a block device"},

	// pipe-to-shell: piping fetched/decoded content directly into a shell.
	{regexp.MustCompile(`\|\s*(sudo\s+)?(sh|bash|zsh|ksh|dash)\b`), "pipe to a shell interpreter"},

	// find <path> ... -delete: a recursive delete in disguise.
	{regexp.MustCompile(`\bfind\s+\S+\s+.*-delete\b`), "find with -delete"},

	// dd writing to a device in ANY operand order (catches of=/dev even when
	// it precedes if=).
	{regexp.MustCompile(`\bdd\s+.*\bof=/dev/`), "raw write to a device with dd"},

	// shred targeting a device node. The pattern uses zero-or-more flag tokens
	// before /dev/ so that `shred /dev/sda` (no flags) is caught as well as
	// `shred -n 3 /dev/sda`, `shred -vfz /dev/nvme0n1`, etc.
	{regexp.MustCompile(`(?:^|\s)shred\s+(?:\S+\s+)*/dev/\w+`), "shred of a device"},

	// recursive chmod/chown on the root filesystem.
	{regexp.MustCompile(`\bchmod\s+-[a-zA-Z]*R[a-zA-Z]*\s+\S+\s+/(\s|$)`), "recursive chmod on root"},
	{regexp.MustCompile(`\bchown\s+-[a-zA-Z]*R[a-zA-Z]*\s+\S+\s+/(\s|$)`), "recursive chown on root"},

	// redirect-overwrite (single >, truncation) onto a critical system path
	// or an SSH key/host file.
	{regexp.MustCompile(`[^>]>\s*/(etc|boot|dev|sys|proc|bin|sbin|usr|lib|lib64)\b`), "redirect-overwrite of a system file"},
	{regexp.MustCompile(`^>\s*/(etc|boot|dev|sys|proc|bin|sbin|usr|lib|lib64)\b`), "redirect-overwrite of a system file"},
	{regexp.MustCompile(`>\s*~?/?\.ssh/(authorized_keys|known_hosts)\b`), "redirect-overwrite of an SSH key/host file"},
	{regexp.MustCompile(`>\s*\$HOME/\.ssh/(authorized_keys|known_hosts)\b`), "redirect-overwrite of an SSH key/host file"},
}

// reRMForce matches an `rm` invocation that is both recursive and force,
// capturing the first whitespace-delimited target operand. It accepts a
// short flag cluster containing both `r`/`R` and `f` in either order, or the
// long `--recursive`/`--force` pair. The target is validated separately by
// isDangerousRMTarget so /tmp and relative paths can be excluded (RE2 has no
// lookahead).
var reRMForce = regexp.MustCompile(`\brm\s+(?:-[a-zA-Z]*(?:r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*|--recursive\s+--force|--force\s+--recursive)\b([^|;&]*)`)

// IsDangerous reports whether cmd matches a built-in dangerous pattern.
// When it returns true, the second value is a human-readable reason.
//
// This is a conservative guardrail, not a sandbox: it catches common
// catastrophic commands but is not exhaustive. Callers must still honor
// an explicit unsafe/override path for intentional destructive operations.
func IsDangerous(cmd string) (bool, string) {
	normalized := strings.Join(strings.Fields(cmd), " ")

	// Recursive+force rm targeting an absolute system or home path. Handled
	// before the regex table so /tmp and relative-path targets are spared.
	if m := reRMForce.FindStringSubmatch(normalized); m != nil {
		if isDangerousRMTarget(m[1]) {
			return true, "recursive force delete of an absolute or home path"
		}
	}

	for _, p := range dangerousPatterns {
		if p.re.MatchString(normalized) {
			return true, p.reason
		}
	}
	return false, ""
}

// isDangerousRMTarget reports whether any operand following a recursive+force
// rm names an absolute system path (outside /tmp and /var/tmp) or the user's
// home. Relative paths (./build, node_modules, dist) are considered safe.
func isDangerousRMTarget(operands string) bool {
	for _, tok := range strings.Fields(operands) {
		if strings.HasPrefix(tok, "-") {
			continue // additional flags
		}
		switch {
		case tok == "/" || tok == "/*":
			return true
		case tok == "~" || strings.HasPrefix(tok, "~/"):
			return true
		case tok == "$HOME" || strings.HasPrefix(tok, "$HOME/"):
			return true
		case strings.HasPrefix(tok, "/"):
			// Absolute path. Spare the conventional scratch directories.
			if tok == "/tmp" || strings.HasPrefix(tok, "/tmp/") ||
				tok == "/var/tmp" || strings.HasPrefix(tok, "/var/tmp/") {
				continue
			}
			return true
		}
	}
	return false
}
