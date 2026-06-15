package safety

import "regexp"

// redaction is the marker substituted in place of a secret value.
const redaction = "***"

var (
	// reEnvAssign matches KEY=value lines for secret-looking keys. The
	// PASS/SECRET/TOKEN/KEY substrings are intentionally over-inclusive
	// (e.g. MYKEYBOARD=x is masked) — for a security tool, a false
	// positive is the safe failure mode.
	reEnvAssign = regexp.MustCompile(`(?m)\b([A-Z][A-Z0-9_]*(PASS|PASSWORD|SECRET|TOKEN|KEY|APIKEY)[A-Z0-9_]*)=\S+`)
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
	// reBearer matches an Authorization-style bearer token; only the token
	// is redacted, the `Bearer ` keyword is preserved.
	reBearer = regexp.MustCompile(`\b(Bearer\s+)[A-Za-z0-9._~+/=-]+`)

	// --- key/value secrets (redact the value, keep the key) ---

	// reKVAssign matches `key=value` / `export key=value` for secret-looking
	// keys, case-insensitive. The key (including any leading `export `) is
	// preserved and the value redacted.
	reKVAssign = regexp.MustCompile(`(?im)\b((?:export\s+)?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret))=\S+`)
	// reKVColon matches `key: value` for secret-looking keys, case-insensitive.
	reKVColon = regexp.MustCompile(`(?im)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\s*:\s*\S+`)

	// --- password-as-flag ---

	// rePasswordLongFlag matches `--password=value` / `--password value`.
	rePasswordLongFlag = regexp.MustCompile(`(--password)(=|\s+)\S+`)
	// rePasswordShortFlag matches mysql/redis style `-pVALUE` (no space). It
	// requires at least one character after `-p` so a bare `-p` (e.g. a port
	// flag with a following space) is not touched.
	rePasswordShortFlag = regexp.MustCompile(`(^|\s)(-p)\S+`)

	// --- IPv6 ---

	// reIPv6 matches IPv6 addresses (full or compressed `::` forms). It
	// requires at least two colons so ordinary `12:30` timestamps and
	// `host:port` pairs are left alone.
	reIPv6 = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,}(?::|[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4})*\b|\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,}\b`)
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
	// 1. Whole-block / highest-specificity first.
	s = rePrivKey.ReplaceAllString(s, "[redacted private key]")

	// 2. Token shapes — redact the entire token.
	s = reGitHubToken.ReplaceAllString(s, redaction)
	s = reAWSKey.ReplaceAllString(s, redaction)
	s = reSlackToken.ReplaceAllString(s, redaction)
	s = reJWT.ReplaceAllString(s, redaction)
	s = reBearer.ReplaceAllString(s, "${1}"+redaction)

	// 3. Key/value + env secrets — keep the key, redact the value.
	s = reKVAssign.ReplaceAllString(s, "${1}="+redaction)
	s = reKVColon.ReplaceAllString(s, "${1}: "+redaction)
	s = reEnvAssign.ReplaceAllString(s, "$1=***")

	// 4. Password flags.
	s = rePasswordLongFlag.ReplaceAllString(s, "$1="+redaction)
	s = rePasswordShortFlag.ReplaceAllString(s, "${1}${2}"+redaction)

	// 5. Generic network addresses last.
	s = reIPv4.ReplaceAllString(s, "$1.*.*")
	s = reIPv6.ReplaceAllString(s, redaction)
	return s
}
