package safety

import (
	"regexp"
	"strings"
)

var (
	credentialLongFlagPattern      = regexp.MustCompile(`(?i)--([a-z][a-z0-9_-]*)(?:=|\s+)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;]+)`)
	credentialShortPassPattern     = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60"'])\s*(?:&\s*)?(?:sudo(?:\.exe)?\s+)?(?:(?:[^\s/\\]+[/\\])*(?:mariadb-dump|mariadb|mysqldump|mysqladmin|mysql|sshpass)(?:\.exe)?|"(?:(?:\\.|\x60.|[^"\\\x60])*[/\\])?(?:mariadb-dump|mariadb|mysqldump|mysqladmin|mysql|sshpass)(?:\.exe)?"|'(?:(?:''|[^'])*[/\\])?(?:mariadb-dump|mariadb|mysqldump|mysqladmin|mysql|sshpass)(?:\.exe)?')[^\r\n;&|]*?\s+(?-i:-p)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialSSHPassPattern       = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60"'])\s*(?:&\s*)?(?:sudo(?:\.exe)?\s+)?(?:(?:[^\s/\\]+[/\\])*sshpass(?:\.exe)?|"(?:(?:\\.|\x60.|[^"\\\x60])*[/\\])?sshpass(?:\.exe)?"|'(?:(?:''|[^'])*[/\\])?sshpass(?:\.exe)?')[^\r\n;&|]*?\s+(?-i:-p)(?:=|\s*)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialSSHPassPromptPattern = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60"'])\s*(?:&\s*)?(?:sudo(?:\.exe)?\s+)?(?:(?:[^\s/\\]+[/\\])*sshpass(?:\.exe)?|"(?:(?:\\.|\x60.|[^"\\\x60])*[/\\])?sshpass(?:\.exe)?"|'(?:(?:''|[^'])*[/\\])?sshpass(?:\.exe)?')[^\r\n;&|]*?\s+(?-i:-P)(?:=|\s+)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialDockerPassPattern    = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60"'])\s*(?:&\s*)?(?:sudo(?:\.exe)?\s+)?(?:(?:[^\s/\\]+[/\\])*docker(?:\.exe)?|"(?:(?:\\.|\x60.|[^"\\\x60])*[/\\])?docker(?:\.exe)?"|'(?:(?:''|[^'])*[/\\])?docker(?:\.exe)?')(?:\s+--?[a-z][a-z0-9-]*(?:=(?:"(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)|\s+(?:"(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+))?)*\s+login\b[^\r\n;&|]*?\s+(?-i:-p)(?:=|\s*)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialCurlUserPattern      = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60])(?:(?-i:-u|-U)(?:=|\s+)|(?-i:--user|--proxy-user)(?:=|\s+))("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialCurlAttachedPattern  = regexp.MustCompile(`(?im)(?:^|[\s;&|({\x60"'])\s*(?:&\s*)?(?:sudo(?:\.exe)?\s+)?(?:(?:[^\s/\\]+[/\\])*curl(?:\.exe)?|"(?:(?:\\.|\x60.|[^"\\\x60])*[/\\])?curl(?:\.exe)?"|'(?:(?:''|[^'])*[/\\])?curl(?:\.exe)?')[^\r\n;&|]*?\s+(?-i:-u|-U)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;&|]+)`)
	credentialBearerPattern        = regexp.MustCompile(`(?i)\bbearer\s+("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;]+)`)
	credentialURIPattern           = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://([^/\s@'"]+)@[^/\s'"]+`)
	environmentReferencePattern    = regexp.MustCompile(`(?i)^(?:\$[a-z_][a-z0-9_]*|\$env:[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%|\$\{(?:env:)?[a-z_][a-z0-9_]*(?::\?[^}]*)?\})$`)
)

// ContainsCredentialMaterial reports high-confidence plaintext credentials
// that must not be persisted in project paths or reusable commands.
func ContainsCredentialMaterial(value string) bool {
	if rePrivKey.MatchString(value) || reGitHubToken.MatchString(value) ||
		reAWSKey.MatchString(value) || reSlackToken.MatchString(value) || reJWT.MatchString(value) {
		return true
	}
	for _, match := range findCredentialValues(value) {
		if !isEnvironmentReference(value[match.valueStart:match.valueEnd]) {
			return true
		}
	}
	for _, match := range credentialLongFlagPattern.FindAllStringSubmatch(value, -1) {
		if len(match) > 2 && isCredentialKey(match[1]) &&
			!isCredentialReference(match[1], match[2]) && !isEnvironmentReference(match[2]) {
			return true
		}
	}
	for _, pattern := range []*regexp.Regexp{
		credentialShortPassPattern,
		credentialSSHPassPattern,
		credentialDockerPassPattern,
		credentialBearerPattern,
	} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 && !isEnvironmentReference(match[1]) {
				return true
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{credentialCurlUserPattern, credentialCurlAttachedPattern} {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) < 2 {
				continue
			}
			_, password, hasPassword := splitUserPassword(match[1])
			if hasPassword && password != "" && !isEnvironmentReference(password) {
				return true
			}
		}
	}
	for _, match := range credentialURIPattern.FindAllStringSubmatch(value, -1) {
		if len(match) < 3 || isEnvironmentReference(match[2]) {
			continue
		}
		if _, password, hasPassword := splitUserPassword(match[2]); hasPassword {
			if password != "" && !isEnvironmentReference(password) {
				return true
			}
			continue
		}
	}
	return false
}

type credentialValueMatch struct {
	valueStart int
	valueEnd   int
}

// findCredentialValues locates credential-looking assignment and serialized
// key/value values. A small scanner is used instead of a single regexp so one
// value can contain adjacent shell fragments, ANSI-C quotes, or a PowerShell
// here-string without leaving a literal suffix unexamined.
func findCredentialValues(value string) []credentialValueMatch {
	matches := make([]credentialValueMatch, 0)
	for offset := 0; offset < len(value); {
		key, keyStart, next, ok := scanCredentialKey(value, offset)
		if !ok {
			offset++
			continue
		}

		cursor := skipCredentialSpace(value, next)
		if cursor >= len(value) || value[cursor] != '=' && value[cursor] != ':' {
			offset = next
			continue
		}
		if !isCredentialKey(key) || value[cursor] == ':' && isSSHPasswordPromptAt(value, keyStart) {
			offset = next
			continue
		}

		cursor = skipCredentialSpace(value, cursor+1)
		end := scanCredentialValueEnd(value, cursor)
		if end <= cursor {
			offset = next
			continue
		}
		matches = append(matches, credentialValueMatch{valueStart: cursor, valueEnd: end})
		offset = end
	}
	return matches
}

func scanCredentialKey(value string, offset int) (key string, keyStart, next int, ok bool) {
	if hasFoldPrefix(value[offset:], "${env:") {
		start := offset + len("${env:")
		end := scanCredentialName(value, start)
		if end > start && end < len(value) && value[end] == '}' {
			return value[start:end], start, end + 1, true
		}
	}
	if hasFoldPrefix(value[offset:], "$env:") {
		start := offset + len("$env:")
		end := scanCredentialName(value, start)
		if end > start {
			return value[start:end], start, end, true
		}
	}

	if value[offset] == '\'' || value[offset] == '"' {
		quote := value[offset]
		start := offset + 1
		end := scanCredentialName(value, start)
		if end > start && end < len(value) && value[end] == quote {
			return value[start:end], start, end + 1, true
		}
		return "", 0, 0, false
	}

	if !isCredentialNameStart(value[offset]) || offset > 0 && isCredentialNameByte(value[offset-1]) {
		return "", 0, 0, false
	}
	end := scanCredentialName(value, offset)
	return value[offset:end], offset, end, true
}

func scanCredentialName(value string, offset int) int {
	for offset < len(value) && isCredentialNameByte(value[offset]) {
		offset++
	}
	return offset
}

func scanCredentialValueEnd(value string, offset int) int {
	if offset >= len(value) {
		return offset
	}
	if offset+1 < len(value) && value[offset] == '@' && (value[offset+1] == '\'' || value[offset+1] == '"') {
		terminator := string(value[offset+1]) + "@"
		if end := strings.Index(value[offset+2:], terminator); end >= 0 {
			return offset + 2 + end + len(terminator)
		}
		return len(value)
	}

	quote := byte(0)
	for cursor := offset; cursor < len(value); cursor++ {
		current := value[cursor]
		if quote != 0 {
			if (current == '\\' || current == '`') && cursor+1 < len(value) {
				cursor++
				continue
			}
			if quote == '\'' && current == '\'' && cursor+1 < len(value) && value[cursor+1] == '\'' {
				cursor++
				continue
			}
			if current == quote {
				quote = 0
			}
			continue
		}

		if current == '$' && cursor+1 < len(value) && value[cursor+1] == '{' {
			if closeOffset := strings.IndexByte(value[cursor+2:], '}'); closeOffset >= 0 {
				cursor += closeOffset + 2
				continue
			}
		}
		if current == '$' && cursor+1 < len(value) && value[cursor+1] == '\'' {
			quote = '\''
			cursor++
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			continue
		}
		if isCredentialValueTerminator(current) {
			return cursor
		}
	}
	return len(value)
}

func skipCredentialSpace(value string, offset int) int {
	for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t') {
		offset++
	}
	return offset
}

func isCredentialValueTerminator(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == ';' || value == ',' || value == '}'
}

func isCredentialNameStart(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isCredentialNameByte(value byte) bool {
	return isCredentialNameStart(value) || value >= '0' && value <= '9' || value == '_' || value == '-'
}

func hasFoldPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func isCredentialKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.HasSuffix(normalized, "_file") || strings.HasSuffix(normalized, "_path") ||
		strings.HasSuffix(normalized, "_stdin") {
		return false
	}
	for _, part := range strings.Split(normalized, "_") {
		switch part {
		case "pass", "password", "passwd", "pwd", "secret", "token":
			return true
		}
	}
	compact := strings.ReplaceAll(normalized, "_", "")
	if compact == "dbpass" {
		return true
	}
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

func isCredentialReference(key, material string) bool {
	normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.HasSuffix(normalizedKey, "_file") || strings.HasSuffix(normalizedKey, "_path") ||
		strings.HasSuffix(normalizedKey, "_stdin") {
		return true
	}

	material = trimOuterQuotes(material)
	if normalizedKey != "secret" {
		return false
	}

	fields := make(map[string]string)
	for _, part := range strings.Split(material, ",") {
		key, value, ok := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return false
		}
		switch key {
		case "id", "src", "source", "env", "type":
		default:
			return false
		}
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		fields[key] = value
	}
	if fields["id"] == "" || fields["src"] != "" && fields["source"] != "" {
		return false
	}
	source := fields["src"]
	if source == "" {
		source = fields["source"]
	}
	if source != "" && fields["env"] != "" {
		return false
	}
	if env := fields["env"]; env != "" && !isEnvironmentName(env) {
		return false
	}
	if secretType := fields["type"]; secretType != "" && secretType != "file" && secretType != "env" {
		return false
	}
	return true
}

func isEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func trimOuterQuotes(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if first == last && (first == '\'' || first == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// splitUserPassword finds the userinfo delimiter without mistaking the colon
// in PowerShell environment references ($env:NAME or ${env:NAME}) for it.
func splitUserPassword(value string) (string, string, bool) {
	value = trimOuterQuotes(value)
	for i := 0; i < len(value); i++ {
		if value[i] == '$' {
			if strings.HasPrefix(value[i:], "${") {
				if end := strings.IndexByte(value[i+2:], '}'); end >= 0 {
					i += end + 2
					continue
				}
			}
			if len(value)-i >= len("$env:") && strings.EqualFold(value[i:i+len("$env:")], "$env:") {
				i += len("$env:")
				for i < len(value) && isEnvironmentNameByte(value[i]) {
					i++
				}
				i--
				continue
			}
		}
		if value[i] == ':' {
			return value[:i], value[i+1:], true
		}
	}
	return value, "", false
}

func isEnvironmentNameByte(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func isEnvironmentReference(value string) bool {
	value = trimOuterQuotes(value)
	return environmentReferencePattern.MatchString(value)
}

func isSSHPasswordPromptAt(value string, keyOffset int) bool {
	for _, match := range credentialSSHPassPromptPattern.FindAllStringSubmatchIndex(value, -1) {
		if len(match) >= 4 && match[2] <= keyOffset && keyOffset < match[3] {
			return true
		}
	}
	return false
}
