//go:build !windows

package commands

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	markmcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/michael-ltm/sshm/internal/config"
	mcppkg "github.com/michael-ltm/sshm/internal/mcp"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Uses only generated identities, a Unix agent and a loopback SSH server.
func localAuthFixture(t *testing.T) (string, *config.Server, agent.Agent, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	for _, name := range []string{"ALL_PROXY", "all_proxy", "SOCKS5_PROXY", "socks5_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gssh.NewSignerFromKey(private)
	require.NoError(t, err)
	ring := agent.NewKeyring()
	require.NoError(t, ring.Add(agent.AddedKey{PrivateKey: private}))
	agentDir, err := os.MkdirTemp("", "sshm-local-agent-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(agentDir) })
	sock := filepath.Join(agentDir, "agent.sock")
	agentListener, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = agentListener.Close() })
	t.Setenv("SSH_AUTH_SOCK", sock)
	go func() {
		for {
			conn, err := agentListener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = agent.ServeAgent(ring, conn) }()
		}
	}()
	accepted := &atomic.Int32{}
	serverConfig := &gssh.ServerConfig{PublicKeyCallback: func(meta gssh.ConnMetadata, key gssh.PublicKey) (*gssh.Permissions, error) {
		if meta.User() != "ops" || !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			return nil, errors.New("wrong identity")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sshConn, channels, requests, err := gssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer sshConn.Close()
				accepted.Add(1)
				go gssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(gssh.Prohibited, "fixture supports sessions only")
						continue
					}
					ch, reqs, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range reqs {
						if request.Type == "pty-req" {
							_ = request.Reply(true, nil)
							continue
						}
						if request.Type != "exec" && request.Type != "shell" {
							_ = request.Reply(false, nil)
							continue
						}
						_ = request.Reply(true, nil)
						_, _ = io.WriteString(ch, "local-agent-connected\n")
						_, _ = ch.SendRequest("exit-status", false, gssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						break
					}
				}
			}()
		}
	}()
	target := &config.Server{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "ops", Auth: config.AuthCloud, CloudEntry: "entry-one", CloudVault: "vault-one"}
	path := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["local-test"] = target
	require.NoError(t, config.Save(path, cfg))
	require.NoError(t, sshpkg.StoreLocalAgentIdentities(path, target, []gssh.PublicKey{signer.PublicKey()}))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".ssh"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0o600))
	return path, target, ring, accepted
}

func TestLocalCloudCLIUsesExistingAgentWithoutVault(t *testing.T) {
	path, target, _, accepted := localAuthFixture(t)
	previous := flagConfigPath
	flagConfigPath = path
	t.Cleanup(func() { flagConfigPath = previous })
	cmd := newExecCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"local-test", "hostname", "--raw-environment"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, output.String(), "local-agent-connected")
	require.NoError(t, connect("local-test", target, false, path))
	require.EqualValues(t, 2, accepted.Load())
}

func TestLocalCloudCLIWithoutIdentityExplainsLocalUnlock(t *testing.T) {
	path, target, ring, accepted := localAuthFixture(t)
	require.NoError(t, ring.RemoveAll())
	previous := flagConfigPath
	flagConfigPath = path
	t.Cleanup(func() { flagConfigPath = previous })
	cmd := newExecCmd()
	cmd.SetArgs([]string{"local-test", "hostname"})
	require.ErrorContains(t, cmd.Execute(), "sshm cloud agent")
	require.ErrorContains(t, connect("local-test", target, false, path), "sshm cloud agent")
	require.Zero(t, accepted.Load())
}

func TestCloudCLIWithoutInventoryBindingUsesCachedLocalIdentity(t *testing.T) {
	path, target, ring, accepted := localAuthFixture(t)
	signers, err := ring.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)
	target.CloudEntry, target.CloudVault = "", ""
	// A known local signing identity does not require rebuilding cloud inventory.
	require.NoError(t, sshpkg.StoreLocalAgentIdentities(path, target, []gssh.PublicKey{signers[0].PublicKey()}))
	previous := flagConfigPath
	flagConfigPath = path
	t.Cleanup(func() { flagConfigPath = previous })
	require.NoError(t, connect("local-test", target, false, path))
	require.EqualValues(t, 1, accepted.Load())
}

func TestCloudLinkedAgentCLIWithoutSignersExplainsLocalUnlock(t *testing.T) {
	path, target, ring, accepted := localAuthFixture(t)
	require.NoError(t, ring.RemoveAll())
	target.Auth = config.AuthAgent
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.Servers["local-test"] = target
	require.NoError(t, config.Save(path, cfg))
	previous := flagConfigPath
	flagConfigPath = path
	t.Cleanup(func() { flagConfigPath = previous })
	cmd := newExecCmd()
	cmd.SetArgs([]string{"local-test", "hostname"})
	require.ErrorContains(t, cmd.Execute(), "sshm cloud agent")
	require.ErrorContains(t, connect("local-test", target, false, path), "sshm cloud agent")
	require.Zero(t, accepted.Load())
}

func TestBrowserLocalTargetCannotBypassCloudJumpAuthorization(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		t.Run(fmt.Sprint("read-only=", readOnly), func(t *testing.T) {
			path, jump, _, accepted := localAuthFixture(t)
			cfg, err := config.Load(path)
			require.NoError(t, err)
			target := *jump
			target.Auth = config.AuthAgent
			target.CloudEntry, target.CloudVault = "", ""
			target.ProxyJump = "local-test"
			cfg.Servers["native-target"] = &target
			require.NoError(t, config.Save(path, cfg))
			session := mcppkg.NewCloudSession(path)
			t.Cleanup(session.Close)
			s, _ := mcppkg.NewServer(mcppkg.Deps{ConfigPath: path, AuditPath: filepath.Join(t.TempDir(), "audit.log"), AllowWrite: !readOnly, CloudSession: session})
			result, err := s.GetTool("check_ssh").Handler(context.Background(), markmcp.CallToolRequest{Params: markmcp.CallToolParams{Name: "check_ssh", Arguments: map[string]any{"alias": "native-target"}}})
			require.NoError(t, err)
			encoded, err := json.Marshal(result)
			require.NoError(t, err)
			if readOnly {
				require.Contains(t, string(encoded), "read-only")
			} else {
				require.Contains(t, string(encoded), "cloud_unlock")
			}
			require.Zero(t, accepted.Load(), "neither cloud jump nor direct fallback may authenticate")
		})
	}
}

func TestLocalDefaultMCPExecAndBrowserFailClosedWithExistingAgent(t *testing.T) {
	path, _, ring, accepted := localAuthFixture(t)
	for _, mode := range []string{"local", "browser", "browser-read-only"} {
		deps := mcppkg.Deps{ConfigPath: path, AuditPath: filepath.Join(t.TempDir(), "audit.log"), AllowWrite: mode != "browser-read-only"}
		if mode != "local" {
			deps.CloudSession = mcppkg.NewCloudSession(path)
			t.Cleanup(deps.CloudSession.Close)
		}
		s, _ := mcppkg.NewServer(deps)
		toolName := "exec"
		args := map[string]any{"alias": "local-test", "command": "hostname", "reason": "test local agent", "raw_environment": true}
		if mode == "browser-read-only" {
			toolName = "check_ssh"
			args = map[string]any{"alias": "local-test"}
		}
		result, err := s.GetTool(toolName).Handler(context.Background(), markmcp.CallToolRequest{Params: markmcp.CallToolParams{Name: toolName, Arguments: args}})
		require.NoError(t, err)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		if mode == "local" {
			require.Contains(t, string(encoded), "local-agent-connected")
			require.Nil(t, s.GetTool("cloud_unlock"))
		} else {
			require.NotContains(t, string(encoded), "local-agent-connected")
			if mode == "browser" {
				require.Contains(t, string(encoded), "cloud_unlock")
			} else {
				require.Contains(t, string(encoded), "read-only")
				require.Nil(t, s.GetTool("cloud_unlock"))
			}
		}
	}
	require.EqualValues(t, 1, accepted.Load(), "browser modes must not authenticate via available local agent")
	require.NoError(t, ring.RemoveAll())
	s, _ := mcppkg.NewServer(mcppkg.Deps{ConfigPath: path, AllowWrite: true})
	result, err := s.GetTool("exec").Handler(context.Background(), markmcp.CallToolRequest{Params: markmcp.CallToolParams{Name: "exec", Arguments: map[string]any{"alias": "local-test", "command": "hostname", "reason": "test locked agent"}}})
	require.NoError(t, err)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "sshm cloud agent")
}
