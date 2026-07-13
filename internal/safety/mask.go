package safety

import (
	"net"
	"regexp"
)

// redaction is the marker substituted in place of a secret value.
const redaction = "***"

var (
	// reIPv4 keeps the first two octets, masks the last two. It will also
	// mask dotted version strings (e.g. 1.2.3.4) — acceptable over-masking.
	reIPv4 = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b`)
	// rePrivKey matches a whole PEM private-key block.
	rePrivKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

	// --- token shapes (redact the whole token) ---

	// reGitHubToken matches GitHub personal/OAuth/app/refresh/server tokens.
	reGitHubToken = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)
	// reAWSKey matches AWS access key IDs.
	reAWSKey = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	// reSlackToken matches Slack bot/app/refresh/personal tokens.
	reSlackToken = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)
	// reJWT matches a three-part base64url JWT beginning with the standard
	// `{"alg"...}` header prefix `eyJ`.
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	// --- password-as-flag ---

	// rePasswordLongFlag matches `--password=value` / `--password value`.
	rePasswordLongFlag = regexp.MustCompile(`(--password)(=|\s+)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;]+)`)
	// rePasswordShortFlag matches mysql/redis style `-pVALUE` (no space). It
	// requires at least one character after `-p` so a bare `-p` (e.g. a port
	// flag with a following space) is not touched. This intentionally also
	// catches flag names like -post and -port — masking a flag name is cosmetic,
	// but leaking a password is a security failure; we accept the false positive.
	rePasswordShortFlag = regexp.MustCompile(`(^|\s)(-p)("(?:\\.|\x60.|[^"\\\x60])*"|'(?:''|[^'])*'|[^\s;]+)`)

	// --- IPv6 ---

	// IPv6 candidates are validated with net.ParseIP and identifier boundaries
	// before masking, so PowerShell's :: member operator is left intact.
	reIPv6Candidate = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+`)
)

// MaskSecrets redacts sensitive data from text that may be shown to an AI
// assistant or written to a log.
//
// Coverage: PEM private-key blocks (removed wholesale), high-confidence token
// shapes (GitHub/AWS/Slack/JWT/Bearer), key/value and env secrets
// (password/token/secret/api-key/... in `k=v`, `k: v` and `export k=v`
// forms), mysql/redis password flags (`-pVALUE`, `--password=...`), and
// IPv4/IPv6 addresses.
//
// Ordering is deliberate: the private-key block is removed first so its body
// is never partially corrupted; specific token and key/value patterns run
// before the generic IP patterns to avoid odd double-masking.
func MaskSecrets(s string) string {
	s = maskCredentialMaterial(s)

	// Generic network addresses are privacy-sensitive in remote output, but are
	// deliberately excluded from audit aliases where exact target identity is
	// required for traceability.
	s = reIPv4.ReplaceAllString(s, "$1.*.*")
	s = maskIPv6Addresses(s)
	return s
}

func maskCredentialMaterial(s string) string {
	// 1. Whole-block / highest-specificity first.
	s = rePrivKey.ReplaceAllString(s, "[redacted private key]")

	// 2. Token shapes — redact the entire token.
	s = reGitHubToken.ReplaceAllString(s, redaction)
	s = reAWSKey.ReplaceAllString(s, redaction)
	s = reSlackToken.ReplaceAllString(s, redaction)
	s = reJWT.ReplaceAllString(s, redaction)
	s = maskCredentialSubmatch(s, credentialBearerPattern)

	// 3. Key/value + env secrets — keep the key, redact the value.
	s = maskCredentialValues(s)

	// 4. Contextual command credentials and password flags.
	s = maskCredentialSubmatch(s, credentialSSHPassPattern)
	s = maskCredentialSubmatch(s, credentialDockerPassPattern)
	s = maskCurlCredentials(s)
	s = maskURIPasswords(s)
	s = rePasswordLongFlag.ReplaceAllString(s, "$1="+redaction)
	s = rePasswordShortFlag.ReplaceAllString(s, "${1}${2}"+redaction)

	return s
}

func maskCredentialValues(s string) string {
	matches := findCredentialValues(s)
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		material := s[match.valueStart:match.valueEnd]
		if isEnvironmentReference(material) {
			continue
		}
		replacement := redaction
		if len(material) >= 2 && (material[0] == '\'' || material[0] == '"') && material[len(material)-1] == material[0] {
			replacement = material[:1] + redaction + material[len(material)-1:]
		}
		s = s[:match.valueStart] + replacement + s[match.valueEnd:]
	}
	return s
}

func maskIPv6Addresses(s string) string {
	matches := reIPv6Candidate.FindAllStringIndex(s, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		start, end := matches[i][0], matches[i][1]
		for start < end && s[start] == '.' {
			start++
		}
		for end > start && s[end-1] == '.' {
			end--
		}
		candidate := s[start:end]
		if candidate == "::" || net.ParseIP(candidate) == nil ||
			start > 0 && (isIdentifierByte(s[start-1]) || s[start-1] == ']' && len(candidate) >= 2 && candidate[:2] == "::") ||
			end < len(s) && isIdentifierByte(s[end]) {
			continue
		}
		s = s[:start] + redaction + s[end:]
	}
	return s
}

func isIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func maskCurlCredentials(s string) string {
	for _, pattern := range []*regexp.Regexp{credentialCurlUserPattern, credentialCurlAttachedPattern} {
		matches := pattern.FindAllStringSubmatchIndex(s, -1)
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			if len(match) < 4 || match[2] < 0 || match[3] < 0 {
				continue
			}
			argument := s[match[2]:match[3]]
			unquoted := trimOuterQuotes(argument)
			username, password, hasPassword := splitUserPassword(unquoted)
			if !hasPassword || password == "" || isEnvironmentReference(password) {
				continue
			}
			quote := ""
			if len(argument) >= 2 && (argument[0] == '\'' || argument[0] == '"') {
				quote = argument[:1]
			}
			replacement := quote + username + ":" + redaction + quote
			s = s[:match[2]] + replacement + s[match[3]:]
		}
	}
	return s
}

func maskURIPasswords(s string) string {
	matches := credentialURIPattern.FindAllStringSubmatchIndex(s, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		if len(match) < 6 || match[4] < 0 || match[5] < 0 {
			continue
		}
		userinfo := s[match[4]:match[5]]
		username, password, hasPassword := splitUserPassword(userinfo)
		if !hasPassword || password == "" || isEnvironmentReference(password) {
			continue
		}
		replacement := username + ":" + redaction
		s = s[:match[4]] + replacement + s[match[5]:]
	}
	return s
}

// maskCredentialSubmatch redacts the first capture group while preserving the
// surrounding command context. Environment references are intentionally kept:
// they point at secret storage but are not secret material themselves.
func maskCredentialSubmatch(s string, pattern *regexp.Regexp) string {
	matches := pattern.FindAllStringSubmatchIndex(s, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		if len(match) < 4 || match[2] < 0 || match[3] < 0 {
			continue
		}
		material := s[match[2]:match[3]]
		if isEnvironmentReference(material) {
			continue
		}
		s = s[:match[2]] + redaction + s[match[3]:]
	}
	return s
}
