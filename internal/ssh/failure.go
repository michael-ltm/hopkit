package ssh

import (
	"context"
	"errors"
	"net"
	"strings"
)

// FailureCategory is safe to persist/sync: no hosts, credentials or stderr.
func FailureCategory(err error) string {
	if err == nil {
		return ""
	}
	var n net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &n) && n.Timeout()) {
		return "timeout"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "host key"), strings.Contains(s, "knownhosts"):
		return "host_key"
	case strings.Contains(s, "unable to authenticate"), strings.Contains(s, "permission denied"):
		return "authentication"
	case strings.Contains(s, "passphrase"), strings.Contains(s, "private key"), strings.Contains(s, "agent"), strings.Contains(s, "key file"):
		return "credential"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "no such host"):
		return "dns"
	default:
		return "connection"
	}
}
