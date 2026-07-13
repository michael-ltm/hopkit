package safety

import (
	"regexp"
	"strings"
)

var (
	credentialAssignmentPattern = regexp.MustCompile(`(?i)\b(?:export\s+)?([a-z][a-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialColonPattern      = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_-]*)\s*:\s*("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialLongFlagPattern   = regexp.MustCompile(`(?i)--([a-z][a-z0-9_-]*)(?:=|\s+)("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialShortPassPattern  = regexp.MustCompile(`(?i)(?:^|[;&|])\s*(?:sudo(?:\.exe)?\s+)?(?:[^\s/\\]+[/\\])*(?:mariadb-dump|mariadb|mysqldump|mysqladmin|mysql|sshpass)(?:\.exe)?\b[^\r\n;&|]*?\s+-p("[^"]*"|'[^']*'|[^\s;&|]+)`)
	credentialBearerPattern     = regexp.MustCompile(`(?i)\bbearer\s+("[^"]*"|'[^']*'|[^\s;]+)`)
	credentialURIPattern        = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://([^/\s@'"]+)@[^/\s'"]+`)
	environmentReferencePattern = regexp.MustCompile(`(?i)^(?:\$[a-z_][a-z0-9_]*|\$env:[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%|\$\{(?:env:)?[a-z_][a-z0-9_]*(?::\?[^}]*)?\})$`)
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
		credentialLongFlagPattern,
	} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 2 && isCredentialKey(match[1]) && !isEnvironmentReference(match[2]) {
				return true
			}
		}
	}
	for _, match := range credentialColonPattern.FindAllStringSubmatchIndex(value, -1) {
		if len(match) < 6 || match[2] < 0 || match[3] < 0 || match[4] < 0 || match[5] < 0 {
			continue
		}
		key := value[match[2]:match[3]]
		material := value[match[4]:match[5]]
		if isCredentialKey(key) && !isEnvironmentReference(material) && !isEnvironmentReferenceAt(value, match[2]) {
			return true
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
	}
	return false
}

func isCredentialKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.HasSuffix(normalized, "_key_path") || strings.HasSuffix(normalized, "_key_file") {
		return false
	}
	for _, part := range strings.Split(normalized, "_") {
		switch part {
		case "pass", "password", "passwd", "pwd", "secret", "token":
			return true
		}
	}
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range []string{
		"password", "passwd", "token", "secret", "apikey", "accesskey", "privatekey", "clientsecret",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	if strings.HasSuffix(normalized, "_key") && normalized != "public_key" && !strings.HasSuffix(normalized, "_public_key") {
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

func isEnvironmentReferenceAt(value string, keyOffset int) bool {
	if keyOffset < 2 || value[keyOffset-2:keyOffset] != "${" {
		return false
	}
	closeOffset := strings.IndexByte(value[keyOffset:], '}')
	if closeOffset < 0 {
		return false
	}
	return isEnvironmentReference(value[keyOffset-2 : keyOffset+closeOffset+1])
}
