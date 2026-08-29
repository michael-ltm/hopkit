// Package pair implements one-time, local-network SSH enrollment.
//
// The controlling sshm process opens a short-lived HTTP callback protected by
// a random bearer token. The target-side script installs/starts OpenSSH,
// appends only the generated public key, and reports the actual local username
// back to sshm. Private keys and passwords never leave the controlling host.
package pair

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxReportBytes = 8 << 10

// Report is the non-secret identity metadata returned by the target script.
type Report struct {
	User     string `json:"user"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
}

// NewToken returns a high-entropy URL-safe one-time token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate pair token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CallbackPath returns the unguessable endpoint path for a pairing session.
func CallbackPath(token string) string { return "/v1/pair/" + token }

// CallbackURL builds a callback URL, adding IPv6 brackets when required.
func CallbackURL(host string, port int, token string) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + CallbackPath(token)
}

// Handler enqueues exactly one valid target report. An identical retry is
// acknowledged without being enqueued again; conflicting duplicates and
// invalid requests never expose the expected token.
func Handler(token string, reports chan<- Report) http.Handler {
	return HandlerWithRetrySignal(token, reports, nil)
}

// HandlerWithRetrySignal behaves like Handler and additionally signals after
// an identical retry has received its 202 response. Pairing commands use this
// to keep the callback listener alive until the target confirms the first
// response was received, without adding a fixed delay to the normal path.
func HandlerWithRetrySignal(token string, reports chan<- Report, retries chan<- struct{}) http.Handler {
	var mu sync.Mutex
	accepted := false
	var acceptedReport Report
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != CallbackPath(token) {
			http.NotFound(w, r)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxReportBytes)
		report, err := decodeReport(r)
		if err != nil {
			http.Error(w, `{"error":"invalid pair report"}`, http.StatusBadRequest)
			return
		}
		if err := validateReport(report); err != nil {
			http.Error(w, `{"error":"invalid pair report"}`, http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if accepted {
			if report == acceptedReport {
				// The target retries callbacks because the first 202 response may
				// be lost. A byte-equivalent normalized report is idempotent and
				// must not turn a successful enrollment into a target-side error.
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, `{"accepted":true,"duplicate":true}`)
				if retries != nil {
					select {
					case retries <- struct{}{}:
					default:
					}
				}
				return
			}
			http.Error(w, `{"error":"pair report already received"}`, http.StatusConflict)
			return
		}
		select {
		case reports <- report:
			accepted = true
			acceptedReport = report
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"accepted":true}`)
		default:
			http.Error(w, `{"error":"pair report queue unavailable"}`, http.StatusServiceUnavailable)
		}
	})
}

func decodeReport(r *http.Request) (Report, error) {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		var report Report
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			return Report{}, err
		}
		return normalizeReport(report), nil
	}
	if err := r.ParseForm(); err != nil {
		return Report{}, err
	}
	return normalizeReport(Report{
		User:     r.Form.Get("user"),
		Hostname: r.Form.Get("hostname"),
		Platform: r.Form.Get("platform"),
	}), nil
}

func normalizeReport(report Report) Report {
	report.User = strings.TrimSpace(report.User)
	report.Hostname = strings.TrimSpace(report.Hostname)
	report.Platform = strings.ToLower(strings.TrimSpace(report.Platform))
	return report
}

func validateReport(report Report) error {
	if err := validIdentityField("user", report.User, 128); err != nil {
		return err
	}
	if err := validIdentityField("hostname", report.Hostname, 255); err != nil {
		return err
	}
	switch report.Platform {
	case "windows", "linux", "darwin", "freebsd", "other-posix":
		return nil
	default:
		return fmt.Errorf("unsupported platform %q", report.Platform)
	}
}

func validIdentityField(name, value string, max int) error {
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if len([]rune(value)) > max || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

// DiscoverCallbackHost asks the operating system which local address it
// would use to reach target. This naturally chooses a Tailscale address for a
// tailnet target and the matching LAN interface for a LAN target. Pairing is
// intentionally limited to loopback/private/CGNAT routes because
// the one-time callback is plain HTTP and is designed for trusted local
// networks, not the public Internet. IPv6 link-local addresses are rejected:
// a portable target-side command cannot reliably preserve their interface zone.
func DiscoverCallbackHost(target string, port int) (string, error) {
	target = strings.TrimSpace(strings.Trim(target, "[]"))
	if target == "" {
		return "", fmt.Errorf("target host is empty")
	}
	if port == 0 {
		port = 22
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("udp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		return "", fmt.Errorf("discover callback route to %s: %w", target, err)
	}
	local := conn.LocalAddr()
	remote := conn.RemoteAddr()
	_ = conn.Close()
	udpAddr, ok := local.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return "", fmt.Errorf("discover callback route to %s: no local IP", target)
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return "", fmt.Errorf("discover callback route to %s: invalid local IP", target)
	}
	ip = ip.Unmap()
	remoteAddr, ok := remote.(*net.UDPAddr)
	if !ok || remoteAddr.IP == nil {
		return "", fmt.Errorf("discover callback route to %s: no remote IP", target)
	}
	remoteIP, ok := netip.AddrFromSlice(remoteAddr.IP)
	if !ok {
		return "", fmt.Errorf("discover callback route to %s: invalid remote IP", target)
	}
	remoteIP = remoteIP.Unmap()
	if !trustedCallbackIP(remoteIP) {
		return "", fmt.Errorf("target %s resolves to an unsupported public, TUN, or IPv6 link-local address %s; direct pairing requires a LAN/Tailscale address (or an explicitly reachable --callback-host)", target, remoteIP)
	}
	if !trustedCallbackIP(ip) {
		return "", fmt.Errorf("automatic callback address %s is public, a TUN fake IP, or IPv6 link-local; use --callback-host with a reachable Tailscale or LAN address", ip)
	}
	return ip.String(), nil
}

// ValidateCallbackHost validates an explicitly supplied callback address.
// Hostnames are allowed because tailnet MagicDNS names cannot be classified
// until the target resolves them; IP literals must still be private and not
// IPv6 link-local.
func ValidateCallbackHost(host string) error {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || strings.ContainsAny(host, "\x00\r\n/?#") {
		return fmt.Errorf("callback host must be a hostname or IP address without a port")
	}
	canonicalHost := strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(canonicalHost); err == nil {
		if !trustedCallbackIP(ip.Unmap()) {
			return fmt.Errorf("callback host %s is public, a TUN fake IP, or IPv6 link-local; use a reachable Tailscale or LAN address", host)
		}
		return nil
	}
	if strings.ContainsRune(host, ':') {
		return fmt.Errorf("callback host must be a hostname or IP address without a port")
	}
	if looksLikeLegacyNumericAddress(canonicalHost) {
		return fmt.Errorf("callback host must not use a legacy numeric IP representation")
	}
	if !validCallbackHostname(host) {
		return fmt.Errorf("callback host must be a valid hostname or IP address without a port")
	}
	lookupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", canonicalHost); err == nil {
		for _, address := range addresses {
			if !trustedCallbackIP(address.Unmap()) {
				return fmt.Errorf("callback hostname %s resolves to a public, TUN, or IPv6 link-local address %s; use a reachable Tailscale or LAN address", host, address.Unmap())
			}
		}
	}
	return nil
}

func looksLikeLegacyNumericAddress(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		digits := part
		base := byte(10)
		if len(digits) > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X') {
			base = 16
			digits = digits[2:]
		} else if len(digits) > 1 && digits[0] == '0' {
			base = 8
			digits = digits[1:]
		}
		if digits == "" {
			return false
		}
		for _, character := range digits {
			valid := character >= '0' && character <= '9'
			if base == 8 {
				valid = character >= '0' && character <= '7'
			} else if base == 16 {
				valid = (character >= '0' && character <= '9') ||
					(character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')
			}
			if !valid {
				return false
			}
		}
	}
	return true
}

func validCallbackHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func trustedCallbackIP(ip netip.Addr) bool {
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Tailscale uses the shared CGNAT range 100.64.0.0/10.
	tailnet := netip.MustParsePrefix("100.64.0.0/10")
	return tailnet.Contains(ip)
}

// RedactedURL removes the one-time token before a callback address is shown
// in diagnostics or errors.
func RedactedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid callback URL>"
	}
	u.Path = "/v1/pair/<redacted>"
	u.RawQuery = ""
	return u.String()
}
