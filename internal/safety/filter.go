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
	{regexp.MustCompile(`\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(/|/\*|~)(\s|$)`), "recursive delete of a root-level or home path"},
	{regexp.MustCompile(`\bmkfs(\.\w+)?\s`), "filesystem creation (mkfs)"},
	{regexp.MustCompile(`\bdd\s+.*of=/dev/`), "raw write to a device with dd"},
	{regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`), "fork bomb"},
	{regexp.MustCompile(`\bchmod\s+-[a-z]*R[a-z]*\s+0{3,4}\s+/(\s|$)`), "recursive chmod 000 on root"},
	{regexp.MustCompile(`>\s*/dev/(sd|nvme|hd|vd)\w*`), "redirect to a block device"},
}

// IsDangerous reports whether cmd matches a built-in dangerous pattern.
// When it returns true, the second value is a human-readable reason.
func IsDangerous(cmd string) (bool, string) {
	normalized := strings.Join(strings.Fields(cmd), " ")
	for _, p := range dangerousPatterns {
		if p.re.MatchString(normalized) {
			return true, p.reason
		}
	}
	return false, ""
}
