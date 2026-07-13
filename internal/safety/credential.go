package safety

import (
	"regexp"
	"strings"
)

var (
	credentialAssignmentPattern   = regexp.MustCompile(`(?i)\b(?:export\s+)?(?:[a-z0-9]+_)*(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|client_?secret)(?:_[a-z0-9]+)*\s*=\s*("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialPasswordFlagPattern = regexp.MustCompile(`(?i)--password(?:=|\s+)("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialBearerPattern       = regexp.MustCompile(`(?i)\bbearer\s+("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialURLPattern          = regexp.MustCompile(`(?i)\bhttps?://[^/\s:@'"]+:([^@/\s'"]+)@[^/\s'"]+`)
	environmentReferencePattern   = regexp.MustCompile(`(?i)^(?:\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$env:[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%)$`)
)

// ContainsCredentialMaterial reports high-confidence plaintext credentials
// that must not be persisted in project paths or reusable commands.
func ContainsCredentialMaterial(value string) bool {
	if reGitHubToken.MatchString(value) {
		return true
	}
	for _, pattern := range []*regexp.Regexp{
		credentialAssignmentPattern,
		credentialPasswordFlagPattern,
		credentialBearerPattern,
		credentialURLPattern,
	} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 && !isEnvironmentReference(match[1]) {
				return true
			}
		}
	}
	return false
}

func isEnvironmentReference(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if first == last && (first == '\'' || first == '"') {
			value = value[1 : len(value)-1]
		}
	}
	return environmentReferencePattern.MatchString(value)
}
