package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func hostSigners(t *testing.T) (gssh.Signer, gssh.Signer) {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edSigner, err := gssh.NewSignerFromKey(ed)
	require.NoError(t, err)
	ecSigner, err := gssh.NewSignerFromKey(ec)
	require.NoError(t, err)
	return edSigner, ecSigner
}

// Exercise real negotiation, not just callback invocation: Go's default
// algorithm order chooses ECDSA even when only the Ed25519 key is pinned.
func TestHostKeyNegotiationUsesExistingTrust(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		hashed, changed, revoked, unknown bool
		ca, rsa                           bool
	}{
		{name: "ed25519_only"},
		{name: "hashed_nonstandard_port", hashed: true},
		{name: "changed_key_rejected", changed: true},
		{name: "revoked_key_rejected", revoked: true},
		{name: "unknown_host_pinned", unknown: true},
		{name: "rsa_sha2_trust", rsa: true},
		{name: "certificate_authority", ca: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			path := filepath.Join(home, ".ssh", "known_hosts")
			require.NoError(t, ensureKnownHosts(path))
			ed, ec := hostSigners(t)
			trusted := ed.PublicKey()
			if tc.rsa {
				key, e := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, e)
				ed, e = gssh.NewSignerFromKey(key)
				require.NoError(t, e)
				trusted = ed.PublicKey()
			}
			if tc.ca {
				ca, _ := hostSigners(t)
				trusted = ca.PublicKey()
				cert := &gssh.Certificate{Key: ed.PublicKey(), CertType: gssh.HostCert, ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: gssh.CertTimeInfinity}
				require.NoError(t, cert.SignCert(rand.Reader, ca))
				var e error
				ed, e = gssh.NewCertSigner(cert, ed)
				require.NoError(t, e)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			address := listener.Addr().String()
			entryHost := knownhosts.Normalize(address)
			if tc.hashed {
				entryHost = knownhosts.HashHostname(entryHost)
			}
			if !tc.unknown {
				key := trusted
				if tc.changed {
					other, _ := hostSigners(t)
					key = other.PublicKey()
				}
				line := knownhosts.Line([]string{entryHost}, key) + "\n"
				if tc.revoked {
					line = "@revoked " + line
				}
				if tc.ca {
					line = "@cert-authority\t" + line
				}
				require.NoError(t, os.WriteFile(path, []byte(line), 0600))
			}
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			serverCfg := &gssh.ServerConfig{NoClientAuth: true}
			serverCfg.AddHostKey(ec)
			if !tc.revoked {
				serverCfg.AddHostKey(ed)
			} else {
				serverCfg = &gssh.ServerConfig{NoClientAuth: true}
				serverCfg.AddHostKey(ed)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				c, _, _, e := gssh.NewServerConn(conn, serverCfg)
				if e == nil {
					c.Close()
				}
			}()
			host, _, err := net.SplitHostPort(address)
			require.NoError(t, err)
			srv := &config.Server{Host: host, Port: listener.Addr().(*net.TCPAddr).Port, User: "fixture", Auth: config.AuthPassword}
			cfg, closer, err := BuildClientConfig(srv, BuildOpts{Password: "fixture", Timeout: 5 * time.Second})
			require.NoError(t, err)
			defer closer.Close()
			client, err := gssh.Dial("tcp", address, cfg)
			if tc.changed || tc.revoked {
				require.Error(t, err)
				if tc.changed {
					require.Contains(t, err.Error(), "host key mismatch")
				}
				if tc.revoked {
					require.Contains(t, err.Error(), "revoked")
				}
			} else {
				require.NoError(t, err)
				client.Close()
			}
			<-done
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			if !tc.unknown {
				require.Equal(t, before, after, "negotiation must not rewrite trust")
			} else {
				require.NotEmpty(t, after)
			}
		})
	}
}

func TestPreferredHostKeyAlgorithmsMatchesKnownHostPatterns(t *testing.T) {
	ed, _ := hostSigners(t)
	for _, tc := range []struct {
		name, pattern, address string
		match                  bool
	}{
		{"wildcard", "*.example.test", "one.example.test:22", true},
		{"negated", "*.example.test,!one.example.test", "one.example.test:22", false},
		{"unrelated", "other.example.test", "one.example.test:22", false},
		{"ipv6_port", "[2001:db8::1]:2222", "[2001:db8::1]:2222", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			line := knownhosts.Line([]string{tc.pattern}, ed.PublicKey()) + "\n"
			require.NoError(t, os.WriteFile(path, []byte(line), 0600))
			algorithms, err := preferredHostKeyAlgorithms(path, tc.address)
			require.NoError(t, err)
			if tc.match {
				require.Equal(t, gssh.KeyAlgoED25519, algorithms[0])
			} else {
				require.Nil(t, algorithms)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "missing")
	algorithms, err := preferredHostKeyAlgorithms(path, "unknown.test:22")
	require.NoError(t, err)
	require.Nil(t, algorithms)
	require.NoError(t, os.WriteFile(path, []byte("invalid known hosts\n"), 0600))
	_, err = preferredHostKeyAlgorithms(path, "unknown.test:22")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "knownhosts"))
}
