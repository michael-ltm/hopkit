package testutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHScenario configures a loopback server using only generated test keys.
type SSHScenario struct {
	Reject, Disconnect, Block string
	Command, Output, Stderr   string
	ExitCode                  uint32
	Echo                      bool
}

type SSHRequest struct {
	Type    string
	Payload []byte
}

type SSHServer struct {
	Target *config.Server
	Path   string
	mu     sync.Mutex
	events []SSHRequest
	closed chan struct{}
}

func (s *SSHServer) Requests() []SSHRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SSHRequest(nil), s.events...)
}

func (s *SSHServer) WaitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH fixture connection leaked")
	}
}

func NewSSHServer(t *testing.T, scenario SSHScenario) *SSHServer {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, name := range []string{"ALL_PROXY", "all_proxy", "SOCKS5_PROXY", "socks5_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gssh.NewSignerFromKey(key)
	require.NoError(t, err)
	block, err := gssh.MarshalPrivateKey(key, "fixture")
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".ssh"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0o600))
	s := &SSHServer{Path: filepath.Join(dir, "config.toml"), Target: &config.Server{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "fixture", Auth: config.AuthKey, KeyPath: keyPath, Platform: "linux"}, closed: make(chan struct{})}
	cfg := config.New()
	cfg.Servers["fixture"] = s.Target
	require.NoError(t, config.Save(s.Path, cfg))
	serverConfig := &gssh.ServerConfig{PublicKeyCallback: func(_ gssh.ConnMetadata, pub gssh.PublicKey) (*gssh.Permissions, error) {
		if scenario.Reject == "authentication" || !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
			return nil, errors.New("fixture authentication denied")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	go func() {
		defer close(s.closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		server, channels, requests, err := gssh.NewServerConn(conn, serverConfig)
		if err != nil {
			return
		}
		defer server.Close()
		go gssh.DiscardRequests(requests)
		for incoming := range channels {
			s.record("session", nil)
			if scenario.Reject == "session" || incoming.ChannelType() != "session" {
				_ = incoming.Reject(gssh.Prohibited, "fixture session denied")
				continue
			}
			ch, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			for r := range requests {
				s.record(r.Type, r.Payload)
				if scenario.Disconnect == r.Type {
					_ = ch.Close()
					return
				}
				if scenario.Block == r.Type {
					continue
				}
				if scenario.Reject == r.Type {
					_ = r.Reply(false, nil)
					continue
				}
				switch r.Type {
				case "pty-req", "window-change":
					_ = r.Reply(true, nil)
				case "shell", "exec":
					_ = r.Reply(true, nil)
					status := scenario.ExitCode
					if r.Type == "exec" && scenario.Command != "" {
						var command struct{ Command string }
						if gssh.Unmarshal(r.Payload, &command) != nil || command.Command != scenario.Command {
							status = 64
						}
					}
					if scenario.Echo {
						go func() { _, _ = io.Copy(ch, ch) }()
						continue
					}
					_, _ = io.WriteString(ch, scenario.Output)
					_, _ = io.WriteString(ch.Stderr(), scenario.Stderr)
					_, _ = ch.SendRequest("exit-status", false, gssh.Marshal(struct{ Status uint32 }{status}))
					_ = ch.Close()
				default:
					_ = r.Reply(false, nil)
				}
			}
			_ = ch.Close()
		}
	}()
	return s
}

func (s *SSHServer) record(kind string, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, SSHRequest{Type: kind, Payload: append([]byte(nil), payload...)})
}
