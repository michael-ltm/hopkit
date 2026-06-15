package ssh

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func TestSocksProxyFromEnv_PrecedenceAndNormalization(t *testing.T) {
	// Ensure a clean slate for every env var we consult.
	clearSocksEnv(t)

	// No env set -> empty.
	hp, auth := socksProxyFromEnv()
	require.Equal(t, "", hp)
	require.Nil(t, auth)

	// HTTPS_PROXY alone, normalized from scheme form.
	t.Setenv("HTTPS_PROXY", "socks5://127.0.0.1:1080")
	hp, auth = socksProxyFromEnv()
	require.Equal(t, "127.0.0.1:1080", hp)
	require.Nil(t, auth)

	// ALL_PROXY wins over HTTPS_PROXY (earlier in precedence list).
	t.Setenv("ALL_PROXY", "socks5h://10.0.0.1:7890")
	hp, auth = socksProxyFromEnv()
	require.Equal(t, "10.0.0.1:7890", hp)
	require.Nil(t, auth)

	// Bare host:port form passes through unchanged.
	t.Setenv("ALL_PROXY", "192.168.1.1:1234")
	hp, auth = socksProxyFromEnv()
	require.Equal(t, "192.168.1.1:1234", hp)
	require.Nil(t, auth)
}

func TestNormalizeSocksAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"socks5://127.0.0.1:7890", "127.0.0.1:7890"},
		{"SOCKS5://127.0.0.1:7890", "127.0.0.1:7890"},
		{"socks5h://host.example:1080", "host.example:1080"},
		{"127.0.0.1:1080", "127.0.0.1:1080"},
		{"http://127.0.0.1:8080", ""}, // unsupported scheme
		{"justahost", ""},             // no port
		// Authenticated forms: host:port is extracted, credentials discarded.
		{"socks5://user:pass@127.0.0.1:1080", "127.0.0.1:1080"},
		{"socks5h://alice:s3cr3t@proxy.example:9050", "proxy.example:9050"},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, normalizeSocksAddr(c.in), "input %q", c.in)
	}
}

func TestParseSocksAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantHP   string
		wantAuth *proxy.Auth
	}{
		// Unauthenticated forms — nil auth.
		{"socks5://127.0.0.1:1080", "127.0.0.1:1080", nil},
		{"socks5h://127.0.0.1:1080", "127.0.0.1:1080", nil},
		{"127.0.0.1:1080", "127.0.0.1:1080", nil},
		// Authenticated socks5://.
		{
			"socks5://user:pass@127.0.0.1:1080",
			"127.0.0.1:1080",
			&proxy.Auth{User: "user", Password: "pass"},
		},
		// Authenticated socks5h://.
		{
			"socks5h://alice:s3cr3t@proxy.example:9050",
			"proxy.example:9050",
			&proxy.Auth{User: "alice", Password: "s3cr3t"},
		},
		// Garbage inputs — empty hostPort, nil auth.
		{"", "", nil},
		{"   ", "", nil},
		{"justahost", "", nil},
		{"http://127.0.0.1:8080", "", nil},
	}
	for _, c := range cases {
		gotHP, gotAuth := parseSocksAddr(c.in)
		require.Equalf(t, c.wantHP, gotHP, "input %q: host:port", c.in)
		require.Equalf(t, c.wantAuth, gotAuth, "input %q: auth", c.in)
	}
}

func TestSubstituteTokens(t *testing.T) {
	out := substituteTokens("nc -X 5 -x 127.0.0.1:7890 %h %p", "example.com", "22", "alice")
	require.Equal(t, "nc -X 5 -x 127.0.0.1:7890 example.com 22", out)

	// Multiple occurrences and %r.
	out = substituteTokens("connect %r@%h:%p then %h again", "h1", "2200", "bob")
	require.Equal(t, "connect bob@h1:2200 then h1 again", out)
}

func TestParseJumpSpec(t *testing.T) {
	cases := []struct {
		spec, defUser string
		want          jumpSpec
		wantErr       bool
	}{
		{"user@host:2222", "fallback", jumpSpec{user: "user", host: "host", port: 2222}, false},
		{"host", "fallback", jumpSpec{user: "fallback", host: "host", port: 22}, false},
		{"host:2200", "fallback", jumpSpec{user: "fallback", host: "host", port: 2200}, false},
		{"bastion.example", "ming", jumpSpec{user: "ming", host: "bastion.example", port: 22}, false},
		{"", "ming", jumpSpec{}, true},
		{"host:notaport", "ming", jumpSpec{}, true},
	}
	for _, c := range cases {
		got, err := parseJumpSpec(c.spec, c.defUser)
		if c.wantErr {
			require.Errorf(t, err, "spec %q", c.spec)
			continue
		}
		require.NoErrorf(t, err, "spec %q", c.spec)
		require.Equalf(t, c.want, got, "spec %q", c.spec)
	}
}

func TestResolveTransportKind_Precedence(t *testing.T) {
	clearSocksEnv(t)

	// ProxyCommand beats everything.
	k, p, a := resolveTransportKind(&config.Server{
		ProxyCommand: "nc %h %p", ProxyJump: "bastion", Proxy: "socks5://127.0.0.1:1080",
	})
	require.Equal(t, kindProxyCommand, k)
	require.Equal(t, "nc %h %p", p)
	require.Nil(t, a)

	// ProxyJump beats Proxy/env SOCKS.
	k, p, a = resolveTransportKind(&config.Server{
		ProxyJump: "bastion", Proxy: "socks5://127.0.0.1:1080",
	})
	require.Equal(t, kindProxyJump, k)
	require.Equal(t, "bastion", p)
	require.Nil(t, a)

	// Explicit Proxy field -> SOCKS5, normalized, no auth.
	k, p, a = resolveTransportKind(&config.Server{Proxy: "socks5://127.0.0.1:1080"})
	require.Equal(t, kindSOCKS5, k)
	require.Equal(t, "127.0.0.1:1080", p)
	require.Nil(t, a)

	// Explicit Proxy with credentials -> SOCKS5 with auth; password not in param.
	k, p, a = resolveTransportKind(&config.Server{Proxy: "socks5://user:pass@127.0.0.1:1080"})
	require.Equal(t, kindSOCKS5, k)
	require.Equal(t, "127.0.0.1:1080", p)
	require.NotNil(t, a)
	require.Equal(t, "user", a.User)
	require.Equal(t, "pass", a.Password)
	require.NotContains(t, p, "pass") // password must not appear in the host:port param

	// Env SOCKS when no per-host proxy.
	t.Setenv("ALL_PROXY", "socks5://10.0.0.1:7890")
	k, p, a = resolveTransportKind(&config.Server{Host: "h"})
	require.Equal(t, kindSOCKS5, k)
	require.Equal(t, "10.0.0.1:7890", p)
	require.Nil(t, a)

	// Direct when nothing configured and no env.
	clearSocksEnv(t)
	k, _, _ = resolveTransportKind(&config.Server{Host: "h"})
	require.Equal(t, kindDirect, k)
}

// TestDial_FallsBackToDirectWhenProxyFails verifies that when a proxy is
// configured but unreachable, Dial retries with a direct TCP dial. We stand up
// a real local TCP listener as the "direct" target and point Proxy at a closed
// port; the SSH handshake against the dummy listener fails, but we assert the
// DIRECT transport was reached via the directDialFunc seam.
func TestDial_FallsBackToDirectWhenProxyFails(t *testing.T) {
	clearSocksEnv(t)

	// Dummy "ssh" listener: accept and immediately close, so the handshake
	// fails but the TCP dial to it succeeds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// Find a port with nothing listening, for the bogus SOCKS proxy.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := closedLn.Addr().String()
	require.NoError(t, closedLn.Close())

	// Observe whether the direct dial seam was hit.
	directReached := false
	orig := directDialFunc
	directDialFunc = func(addr string, timeout time.Duration) (net.Conn, error) {
		directReached = true
		return orig(addr, timeout)
	}
	defer func() { directDialFunc = orig }()

	srv := &config.Server{
		Host: "127.0.0.1", User: "tester", Auth: config.AuthPassword,
		Proxy: "socks5://" + closedAddr,
	}
	// Parse port into the server.
	srv.Port = atoiOrZero(port)

	_, derr := Dial(srv, BuildOpts{Password: "x", Timeout: 2 * time.Second, Insecure: true})
	// Handshake against the dummy listener must fail, but the direct fallback
	// path must have been attempted.
	require.Error(t, derr)
	require.True(t, directReached, "expected direct fallback dial to be attempted")
	// The combined error should name the socks attempt.
	require.Contains(t, strings.ToLower(derr.Error()), "socks5")
}

// TestCmdConn_ReadWriteClose exercises the cmdConn net.Conn adapter against a
// real `cat` process (a perfect echo "proxy"): bytes written to stdin come back
// on stdout. It also verifies Close reaps the process and the deadline setters
// are no-ops.
func TestCmdConn_ReadWriteClose(t *testing.T) {
	// `cat` echoes stdin to stdout, so it stands in for a transparent proxy.
	srv := &config.Server{Host: "127.0.0.1", Port: 22, User: "u", ProxyCommand: "cat"}
	conn, err := dialProxyCommand(srv, srv.ProxyCommand)
	require.NoError(t, err)
	defer conn.Close()

	// Deadline setters must not error (unsupported -> nil).
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, conn.SetReadDeadline(time.Now()))
	require.NoError(t, conn.SetWriteDeadline(time.Now()))
	require.Equal(t, "proxycommand", conn.LocalAddr().Network())

	want := []byte("hello-proxy\n")
	_, err = conn.Write(want)
	require.NoError(t, err)

	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, want, got)

	require.NoError(t, conn.Close())
	// Second close must be safe.
	require.NoError(t, conn.Close())
}

// TestDialProxyCommand_TokenSubstitution confirms the substituted command line
// receives %h/%p/%r values by having the proxy echo them back.
func TestDialProxyCommand_TokenSubstitution(t *testing.T) {
	srv := &config.Server{Host: "example.com", Port: 2222, User: "alice"}
	// printf writes the substituted tokens to stdout; the ssh side reads them.
	conn, err := dialProxyCommand(srv, `printf '%r/%h/%p'`)
	require.NoError(t, err)
	defer conn.Close()

	out, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, "alice/example.com/2222", string(out))
}

// clearSocksEnv unsets every SOCKS-related env var for the duration of the test
// using t.Setenv (which restores prior values automatically).
func clearSocksEnv(t *testing.T) {
	t.Helper()
	for _, k := range socksEnvVars {
		t.Setenv(k, "")
	}
}

func atoiOrZero(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
