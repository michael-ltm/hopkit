package config

import (
	"encoding/hex"
	"strings"
)

// DeviceConnectionID recognizes a client connection without network discovery.
func DeviceConnectionID(s *Server) string {
	if s == nil || (s.Auth != AuthAgent && s.Auth != AuthCloud) || s.User != "sshm-client" || s.Port != 22 {
		return ""
	}
	const prefix, suffix = "sshm-device-", ".invalid"
	if !strings.HasPrefix(s.Host, prefix) || !strings.HasSuffix(s.Host, suffix) {
		return ""
	}
	raw, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(s.Host, prefix), suffix))
	if err != nil || len(raw) < 8 || len(raw) > 100 {
		return ""
	}
	for _, c := range raw {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ""
		}
	}
	return string(raw)
}
