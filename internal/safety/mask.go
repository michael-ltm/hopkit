package safety

import "regexp"

var (
	// reIPv4 keeps the first two octets, masks the last two.
	reIPv4 = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b`)
	// reEnvAssign matches KEY=value lines for secret-looking keys.
	reEnvAssign = regexp.MustCompile(`(?m)\b([A-Z][A-Z0-9_]*(PASS|PASSWORD|SECRET|TOKEN|KEY|APIKEY)[A-Z0-9_]*)=\S+`)
	// rePrivKey matches a whole PEM private-key block.
	rePrivKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
)

// MaskSecrets redacts sensitive data from text that may be shown to an AI
// assistant or written to a log: IPv4 addresses keep their first two
// octets, secret-looking env assignments lose their values, and PEM
// private-key blocks are removed entirely.
func MaskSecrets(s string) string {
	s = rePrivKey.ReplaceAllString(s, "[redacted private key]")
	s = reEnvAssign.ReplaceAllString(s, "$1=***")
	s = reIPv4.ReplaceAllString(s, "$1.*.*")
	return s
}
