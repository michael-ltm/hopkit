package safety

import (
	"regexp"
	"strings"
)

var (
	credentialAssignmentPattern = regexp.MustCompile(`(?i)\b(?:export\s+)?([a-z][a-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialColonPattern      = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_-]*)\s*:\s*("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialLongFlagPattern   = regexp.MustCompile(`(?i)--([a-z][a-z0-9_-]*)(?:=|\s+)("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialShortPassPattern  = regexp.MustCompile(`(?:^|\s)-p("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialBearerPattern     = regexp.MustCompile(`(?i)\bbearer\s+("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialURIPattern        = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://([^/\s@'"]+)@[^/\s'"]+`)
	environmentReferencePattern = regexp.MustCompile(`(?i)^(?:\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$env:[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%)$`)
)

// ContainsCredentialMaterial reports high-confidence plaintext credentials
// that must not be persisted in project paths or reusable commands.
func ContainsCredentialMaterial(value string) bool {
	if rePrivKey.MatchString(value) || reGitHubToken.MatchString(value) ||
		reAWSKey.MatchString(value) || reSlackToken.MatchString(value) || reJWT.MatchString(value) {
		return true
	}
	for _, pattern := range []*regexp.Regexp{
		credentialAssignmentPattern,
		credentialColonPattern,
		credentialLongFlagPattern,
	} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 2 && isCredentialKey(match[1]) && !isEnvironmentReference(match[2]) {
				return true
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{credentialShortPassPattern, credentialBearerPattern} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 && !isEnvironmentReference(match[1]) {
				return true
			}
		}
	}
	for _, match := range credentialURIPattern.FindAllStringSubmatch(value, -1) {
		if len(match) < 3 || isEnvironmentReference(match[2]) {
			continue
		}
		if _, password, hasPassword := strings.Cut(match[2], ":"); hasPassword {
			if password != "" && !isEnvironmentReference(password) {
				return true
			}
			continue
		}
		if credentialUsernameOnlyScheme(match[1]) {
			return true
		}
	}
	return false
}

func isCredentialKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, part := range strings.Split(normalized, "_") {
		switch part {
		case "pass", "password", "passwd", "pwd", "secret", "token":
			return true
		}
	}
	padded := "_" + normalized + "_"
	for _, compound := range []string{
		"api_key", "apikey", "access_key", "accesskey", "private_key", "privatekey",
		"client_secret", "clientsecret",
	} {
		if strings.Contains(padded, "_"+compound+"_") {
			return true
		}
	}
	return false
}

func credentialUsernameOnlyScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "git+http", "git+https":
		return true
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
