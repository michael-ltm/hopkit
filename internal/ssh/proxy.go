package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// transportKind enumerates how the target server is reached. Selection follows
// a fixed precedence (ProxyCommand > ProxyJump > SOCKS5 > Direct); see
// resolveTransportKind.
type transportKind int

const (
	kindDirect transportKind = iota
	kindProxyCommand
	kindProxyJump
	kindSOCKS5
)

func (k transportKind) String() string {
	switch k {
	case kindProxyCommand:
		return "proxy-command"
	case kindProxyJump:
		return "proxy-jump"
	case kindSOCKS5:
		return "socks5"
	default:
		return "direct"
	}
}

// socksEnvVars is the ordered list of environment variables consulted for a
// SOCKS5 proxy. First non-empty wins (matches common tooling: ALL_PROXY then
// SOCKS5_PROXY then HTTPS_PROXY, each in upper/lower form).
var socksEnvVars = []string{
	"ALL_PROXY", "all_proxy",
	"SOCKS5_PROXY", "socks5_proxy",
	"HTTPS_PROXY", "https_proxy",
}

// resolveTransportKind decides how to reach s, returning the kind plus its
// relevant parameter (the ProxyCommand string, the ProxyJump spec, or the
// normalized SOCKS5 host:port). Precedence: ProxyCommand > ProxyJump >
// Proxy/env-SOCKS5 > Direct. The selection performs no I/O so it is unit
// testable.
func resolveTransportKind(s *config.Server) (transportKind, string) {
	if v := strings.TrimSpace(s.ProxyCommand); v != "" {
		return kindProxyCommand, v
	}
	if v := strings.TrimSpace(s.ProxyJump); v != "" {
		return kindProxyJump, v
	}
	if v := normalizeSocksAddr(s.Proxy); v != "" {
		return kindSOCKS5, v
	}
	if v := socksProxyFromEnv(); v != "" {
		return kindSOCKS5, v
	}
	return kindDirect, ""
}

// socksProxyFromEnv returns the normalized host:port of the first SOCKS5 proxy
// found in the environment, or "" if none is set.
func socksProxyFromEnv() string {
	for _, k := range socksEnvVars {
		if v := normalizeSocksAddr(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// normalizeSocksAddr accepts "socks5://host:port", "socks5h://host:port" or a
// bare "host:port" and returns the bare host:port. Empty/whitespace input and
// values lacking a host:port shape return "".
func normalizeSocksAddr(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	for _, scheme := range []string{"socks5://", "socks5h://"} {
		if strings.HasPrefix(strings.ToLower(v), scheme) {
			v = v[len(scheme):]
			break
		}
	}
	v = strings.TrimSpace(v)
	// Require a host:port shape; reject values that still carry a scheme
	// (e.g. http://) we don't support.
	if v == "" || strings.Contains(v, "://") {
		return ""
	}
	if _, _, err := net.SplitHostPort(v); err != nil {
		return ""
	}
	return v
}

// jumpSpec is a resolved ProxyJump hop target.
type jumpSpec struct {
	user string
	host string
	port int
}

// parseJumpSpec parses a "[user@]host[:port]" jump spec. defaultUser is used
// when the spec omits a user; the default port is 22. It does not resolve
// aliases — alias lookup happens in dialViaJump using the loaded config.
func parseJumpSpec(spec, defaultUser string) (jumpSpec, error) {
	v := strings.TrimSpace(spec)
	if v == "" {
		return jumpSpec{}, errors.New("empty proxy jump spec")
	}
	j := jumpSpec{user: defaultUser, port: 22}
	if at := strings.LastIndex(v, "@"); at >= 0 {
		j.user = v[:at]
		v = v[at+1:]
	}
	if strings.Contains(v, ":") {
		host, portStr, err := net.SplitHostPort(v)
		if err != nil {
			return jumpSpec{}, fmt.Errorf("parse proxy jump %q: %w", spec, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return jumpSpec{}, fmt.Errorf("parse proxy jump %q: invalid port", spec)
		}
		j.host = host
		j.port = port
	} else {
		j.host = v
	}
	if j.host == "" {
		return jumpSpec{}, fmt.Errorf("parse proxy jump %q: empty host", spec)
	}
	return j, nil
}

// substituteTokens replaces OpenSSH ProxyCommand tokens in cmd: %h→host,
// %p→port, %r→user. All occurrences are replaced; a literal %% is left intact
// is not specially handled (rare in practice).
func substituteTokens(cmd, host, port, user string) string {
	r := strings.NewReplacer("%h", host, "%p", port, "%r", user)
	return r.Replace(cmd)
}

// syncBuffer is a goroutine-safe bytes buffer. exec writes a process's stderr
// from a private goroutine while the ssh transport reads stdout concurrently;
// guarding stderr with a mutex keeps the race detector quiet.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stubAddr is a net.Addr used by cmdConn, which has no real socket addresses.
type stubAddr struct{ s string }

func (a stubAddr) Network() string { return "proxycommand" }
func (a stubAddr) String() string  { return a.s }

// cmdConn adapts an external process (a ProxyCommand) to net.Conn: it reads
// from the process stdout and writes to its stdin. Close kills the process and
// waits for it to exit. Deadlines are unsupported (the process pipes do not
// honor them); the deadline setters return nil so the ssh transport, which
// sets deadlines defensively, keeps working.
type cmdConn struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stdin  io.WriteCloser
	stderr *syncBuffer
	addr   stubAddr
}

// stderrText returns the captured stderr, trimmed, for inclusion in errors.
func (c *cmdConn) stderrText() string { return strings.TrimSpace(c.stderr.String()) }

func (c *cmdConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *cmdConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

func (c *cmdConn) Close() error {
	// Closing stdin lets a well-behaved proxy exit; then kill to be sure.
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	_ = c.cmd.Wait()
	_ = c.stdout.Close()
	return nil
}

func (c *cmdConn) LocalAddr() net.Addr              { return c.addr }
func (c *cmdConn) RemoteAddr() net.Addr             { return c.addr }
func (c *cmdConn) SetDeadline(time.Time) error      { return nil }
func (c *cmdConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cmdConn) SetWriteDeadline(time.Time) error { return nil }

// directDialFunc is the seam used for the direct (no-proxy) TCP dial. Tests
// override it to observe whether the Direct transport was reached during a
// retry/fallback. It defaults to net.DialTimeout.
var directDialFunc = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

// dialTransport resolves the transport for s (honoring precedence) and returns
// a net.Conn to the target plus any auxiliary closer that must stay open for
// the connection's lifetime (e.g. the ProxyJump SSH client). When forceDirect
// is true the proxy/jump configuration is ignored and a direct TCP dial is
// used. The returned transportKind reports which path was actually taken.
func dialTransport(s *config.Server, opts BuildOpts, timeout time.Duration, forceDirect bool) (net.Conn, io.Closer, error) {
	conn, aux, _, err := dialTransportKind(s, opts, timeout, forceDirect)
	return conn, aux, err
}

func dialTransportKind(s *config.Server, opts BuildOpts, timeout time.Duration, forceDirect bool) (net.Conn, io.Closer, transportKind, error) {
	kind, param := resolveTransportKind(s)
	if forceDirect {
		kind, param = kindDirect, ""
	}
	switch kind {
	case kindProxyCommand:
		conn, err := dialProxyCommand(s, param)
		return conn, nil, kind, err
	case kindProxyJump:
		conn, aux, err := dialViaJump(s, param, opts, timeout)
		return conn, aux, kind, err
	case kindSOCKS5:
		conn, err := dialSOCKS5(s, param, timeout)
		return conn, nil, kind, err
	default:
		conn, err := directDialFunc(Address(s), timeout)
		if err != nil {
			return nil, nil, kindDirect, fmt.Errorf("dial %s: %w", Address(s), err)
		}
		return conn, nil, kindDirect, nil
	}
}

// dialProxyCommand runs the substituted ProxyCommand and returns a net.Conn
// bound to its stdio. The process is started but not waited on; Close reaps it.
func dialProxyCommand(s *config.Server, command string) (net.Conn, error) {
	host := s.Host
	port := strconv.Itoa(portOf(s))
	cmdline := substituteTokens(command, host, port, s.User)

	// Run via the shell so user-provided commands with flags/quoting work as
	// they would under OpenSSH's ProxyCommand.
	cmd := exec.Command("sh", "-c", cmdline)
	stderr := &syncBuffer{}
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy command stdout: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy command stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start proxy command: %w", err)
	}
	return &cmdConn{
		cmd:    cmd,
		stdout: stdout,
		stdin:  stdin,
		stderr: stderr,
		addr:   stubAddr{s: Address(s)},
	}, nil
}

// dialSOCKS5 dials the target through a SOCKS5 proxy at addr (host:port).
func dialSOCKS5(s *config.Server, addr string, timeout time.Duration) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer %s: %w", addr, err)
	}
	conn, err := dialer.Dial("tcp", Address(s))
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s via %s: %w", Address(s), addr, err)
	}
	return conn, nil
}

// dialViaJump establishes an SSH connection to the jump host, then opens a TCP
// connection to the final target through that jump client. The jump *Client is
// returned as an io.Closer so the caller can keep it alive for the lifetime of
// the target connection (closing it would tear down the tunnel). Only a single
// hop is performed: the jump host's own transport may use env SOCKS / its own
// ProxyCommand, but a further ProxyJump on the jump host is NOT followed.
func dialViaJump(s *config.Server, spec string, opts BuildOpts, timeout time.Duration) (net.Conn, io.Closer, error) {
	jump, err := resolveJumpServer(spec, s, opts)
	if err != nil {
		return nil, nil, err
	}

	// Build the jump host's own client config + transport. Reuse the target's
	// insecure/timeout posture but never inherit the target's password.
	jumpOpts := BuildOpts{Insecure: opts.Insecure, Timeout: timeout, ConfigPath: opts.ConfigPath}
	cfg, closer, err := BuildClientConfig(jump, jumpOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy jump %s: %w", Address(jump), err)
	}

	// Reach the jump host. Bound recursion: clear any ProxyJump on the jump so
	// we never chain a second hop.
	jumpForDial := *jump
	jumpForDial.ProxyJump = ""
	jconn, jaux, err := dialTransport(&jumpForDial, jumpOpts, timeout, false)
	if err != nil {
		closer.Close()
		return nil, nil, fmt.Errorf("proxy jump %s: %w", Address(jump), err)
	}

	sshConn, chans, reqs, err := gssh.NewClientConn(jconn, Address(jump), cfg)
	if err != nil {
		jconn.Close()
		if jaux != nil {
			jaux.Close()
		}
		closer.Close()
		return nil, nil, fmt.Errorf("proxy jump handshake %s: %w", Address(jump), err)
	}
	jumpClient := gssh.NewClient(sshConn, chans, reqs)

	target, err := jumpClient.Dial("tcp", Address(s))
	if err != nil {
		jumpClient.Close()
		jconn.Close()
		if jaux != nil {
			jaux.Close()
		}
		closer.Close()
		return nil, nil, fmt.Errorf("proxy jump connect %s via %s: %w", Address(s), Address(jump), err)
	}

	// Keep the jump client, its underlying conn, its aux closers and config
	// closer alive until the target conn closes.
	aux := multiCloser{jumpClient, jconn, jaux, closer}
	return target, aux, nil
}

// resolveJumpServer turns a ProxyJump spec into a *config.Server. The spec may
// be an existing alias in the loaded config or a "[user@]host[:port]" string.
// When the spec is not a known alias it is parsed as a host spec, defaulting
// the user to the target server's user.
func resolveJumpServer(spec string, target *config.Server, opts BuildOpts) (*config.Server, error) {
	v := strings.TrimSpace(spec)
	// Alias resolution requires the config; fall back to the default path.
	path := opts.ConfigPath
	if path == "" {
		path = config.ConfigPath()
	}
	if path != "" {
		if cfg, err := config.Load(path); err == nil {
			if js, ok := cfg.Servers[v]; ok {
				// Use a copy so we never mutate the shared config entry.
				cp := *js
				return &cp, nil
			}
		}
	}
	js, err := parseJumpSpec(v, target.User)
	if err != nil {
		return nil, err
	}
	return &config.Server{Host: js.host, Port: js.port, User: js.user, Auth: config.AuthAgent}, nil
}

// multiCloser closes a set of io.Closers in order, skipping nils, returning the
// first error.
type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, c := range m {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// portOf returns the server port, defaulting to 22.
func portOf(s *config.Server) int {
	if s.Port == 0 {
		return 22
	}
	return s.Port
}
