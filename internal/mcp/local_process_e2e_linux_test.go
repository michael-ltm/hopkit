//go:build linux

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localservice"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Opt-in native proof: no fake protector, cloud session, external SSH Agent,
// credential arguments, user's SSH files, or installed startup service.
func TestNativeLocalCredentialsAcrossCLIAndMCPProcesses(t *testing.T) {
	if os.Getenv("SSHM_DEVICEKEY_E2E") != "1" {
		t.Skip("opt in to native Linux subprocess credential test")
	}
	binary := os.Getenv("SSHM_E2E_BINARY")
	require.True(t, filepath.IsAbs(binary), "SSHM_E2E_BINARY must be an absolute, prebuilt sshm path")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("SSHM_NO_UPDATE_CHECK", "1")
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(home, "nonexistent-agent.sock"))
	for _, name := range []string{"ALL_PROXY", "all_proxy", "SOCKS5_PROXY", "socks5_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := &atomic.Int32{}
	nativeSSHFixture(t, listener, signer, accepted)
	target := &config.Server{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, User: "synthetic-ops", Auth: config.AuthCloud, CloudEntry: "synthetic-offline-entry", CloudVault: "synthetic-offline-vault"}
	path := filepath.Join(home, "config.toml")
	cfg := config.New()
	cfg.Servers["native-fixture"] = target
	require.NoError(t, config.Save(path, cfg))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0600))
	block, err := ssh.MarshalPrivateKey(private, "synthetic-native-e2e")
	require.NoError(t, err)
	credential := localstore.Credential{Key: pem.EncodeToMemory(block)}
	defer localstore.CloseCredentials([]localstore.Credential{credential})
	store := localstore.New(path) // real System protector retained
	require.NoError(t, store.Put(context.Background(), target, []localstore.Credential{credential}))
	nativeProtectionCleanup(t, store)
	envelope, err := os.ReadFile(store.Path())
	require.NoError(t, err)
	require.NotContains(t, string(envelope), "PRIVATE KEY")
	info, err := os.Stat(store.Path())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	sock := localservice.SocketPath(path)
	t.Cleanup(func() { _ = os.Remove(sock); _ = os.Remove(sock + ".lock") })

	// CLI proves direct persistent-store access before any local service exists.
	require.False(t, localservice.Status(path).Running)
	cliCtx, cancelCLI := context.WithTimeout(context.Background(), 15*time.Second)
	output, err := exec.CommandContext(cliCtx, binary, "--config", path, "exec", "native-fixture", "hostname", "--raw-environment").CombinedOutput()
	cancelCLI()
	require.NoError(t, err, "fresh CLI: %s", output)
	require.Contains(t, string(output), "synthetic-native-host")
	require.EqualValues(t, 1, accepted.Load())

	// Own the service child so MCP Ensure cannot leave an untracked daemon.
	stopService := nativeServiceProcess(t, binary, path)
	nativeAgentSignature(t, path, signer.PublicKey(), true)
	first := nativeMCPCheck(t, binary, path)
	assertNativeAuth(t, first, true)
	require.EqualValues(t, 2, accepted.Load())
	stopService()
	require.False(t, localservice.Status(path).Running)
	stopRestarted := nativeServiceProcess(t, binary, path)
	nativeAgentSignature(t, path, signer.PublicKey(), true)
	second := nativeMCPCheck(t, binary, path)
	assertNativeAuth(t, second, true)
	require.EqualValues(t, 3, accepted.Load())
	require.NoError(t, localstore.New(path).Lock(context.Background()))
	nativeAgentSignature(t, path, signer.PublicKey(), false)
	locked := nativeMCPCheck(t, binary, path)
	assertNativeAuth(t, locked, false)
	require.Contains(t, locked, "service unlock")
	require.EqualValues(t, 3, accepted.Load(), "persisted lock must reject a new process before SSH authentication")
	stopRestarted()
}

func nativeAgentSignature(t *testing.T, path string, key ssh.PublicKey, allowed bool) {
	t.Helper()
	conn, err := net.DialTimeout("unix", localservice.SocketPath(path), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	challenge := []byte("synthetic-native-service-restart")
	signature, err := agent.NewClient(conn).Sign(key, challenge)
	if allowed {
		require.NoError(t, err)
		require.NoError(t, key.Verify(challenge, signature))
	} else {
		require.Error(t, err)
	}
}

func nativeSSHFixture(t *testing.T, listener net.Listener, signer ssh.Signer, accepted *atomic.Int32) {
	t.Helper()
	server := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "synthetic-ops" || !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			return nil, errors.New("wrong synthetic identity")
		}
		return nil, nil
	}}
	server.AddHostKey(signer)
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	var clients sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			clients.Add(1)
			go func() {
				defer clients.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(conns, conn); mu.Unlock() }()
				session, channels, requests, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				defer session.Close()
				accepted.Add(1)
				go ssh.DiscardRequests(requests)
				for request := range channels {
					if request.ChannelType() != "session" {
						_ = request.Reject(ssh.Prohibited, "synthetic session only")
						continue
					}
					ch, reqs, err := request.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						if req.Type != "exec" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						_, _ = io.WriteString(ch, "synthetic-native-host\n")
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
						break
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		clients.Wait()
	})
}

func nativeProtectionCleanup(t *testing.T, store *localstore.Store) {
	t.Helper()
	raw, err := os.ReadFile(store.Path())
	require.NoError(t, err)
	var envelope struct {
		Backend string `json:"backend"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	clear(raw)
	t.Logf("native device protection backend: %s", strings.Split(envelope.Backend, ":")[0])
	// Remove only the random Secret Service item generated for this synthetic
	// fixture if the native system chose that backend. No existing item is read.
	if ref, ok := strings.CutPrefix(envelope.Backend, "secret-service:"); ok {
		_, err := hex.DecodeString(ref)
		require.NoError(t, err)
		require.Len(t, ref, 32)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			require.NoError(t, exec.CommandContext(ctx, "secret-tool", "clear", "application", "sshm", "instance", ref).Run())
		})
	}
}

func nativeServiceProcess(t *testing.T, binary, path string) func() {
	t.Helper()
	cmd := exec.Command(binary, "--config", path, "service", "run")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	t.Cleanup(stop)
	require.Eventually(t, func() bool { return localservice.Status(path).Running }, 3*time.Second, 20*time.Millisecond)
	return stop
}

func nativeMCPCheck(t *testing.T, binary, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := exec.CommandContext(ctx, binary, "--config", path, "mcp")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	cleanup := func() { once.Do(func() { _ = stdin.Close(); cancel(); <-done }) }
	t.Cleanup(cleanup)
	defer cleanup()
	type response struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	responses := make(chan response, 8)
	readErrors := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var r response
			if e := json.Unmarshal(scanner.Bytes(), &r); e != nil {
				readErrors <- e
				return
			}
			select {
			case responses <- r:
			case <-ctx.Done():
				return
			}
		}
		readErrors <- scanner.Err()
	}()
	send := func(value any) {
		data, e := json.Marshal(value)
		require.NoError(t, e)
		_, e = stdin.Write(append(data, '\n'))
		require.NoError(t, e)
	}
	receive := func(id int) response {
		for {
			select {
			case r := <-responses:
				if r.ID == id {
					require.Empty(t, r.Error)
					return r
				}
			case e := <-readErrors:
				t.Fatalf("MCP stdout ended or was not JSON: %v", e)
			case <-ctx.Done():
				t.Fatal("MCP response timed out")
			}
		}
	}
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "synthetic-native-e2e", "version": "1"}}})
	_ = receive(1)
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "check_ssh", "arguments": map[string]any{"alias": "native-fixture", "mode": "auth"}}})
	r := receive(2)
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	require.NoError(t, json.Unmarshal(r.Result, &result))
	require.False(t, result.IsError)
	require.Len(t, result.Content, 1)
	return result.Content[0].Text
}

func assertNativeAuth(t *testing.T, text string, ok bool) {
	t.Helper()
	var result struct {
		OK  bool `json:"ok"`
		SSH struct {
			OK bool `json:"ok"`
		} `json:"ssh"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &result))
	require.Equal(t, ok, result.OK)
	require.Equal(t, ok, result.SSH.OK)
	if ok {
		require.NotContains(t, text, "cloud_unlock")
		require.NotContains(t, text, "service unlock")
		require.NotContains(t, text, "service setup")
	}
}
