//go:build !windows

package commands

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	ssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Opt-in real CLI + TTY + HTTPS service + disposable SSH server acceptance.
// All secrets and targets are generated for this test; the account is deleted.
func TestCloudCLIEmptyDevice(t *testing.T) {
	binary, endpoint := os.Getenv("SSHM_CLI_TEST_BINARY"), os.Getenv("SSHM_CLOUD_TEST_ENDPOINT")
	if binary == "" || endpoint == "" {
		t.Skip("set SSHM_CLI_TEST_BINARY and SSHM_CLOUD_TEST_ENDPOINT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	username := "test-" + strings.ToLower(cloudsync.RandomID()[:16])
	password, phrase := []byte(cloudsync.RandomID()), []byte(cloudsync.RandomID())
	defer cloudsync.Wipe(password)
	defer cloudsync.Wipe(phrase)
	vault, recovery, err := cloudsync.NewVault(username, phrase)
	require.NoError(t, err)
	defer vault.Close()
	state, err := cloudsync.Register(ctx, endpoint, username, "synthetic-source", password, vault, recovery)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, state.Request(context.Background(), "DELETE", "/v1/account", map[string]string{"password": string(password)}, nil))
	}()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := ssh.NewSignerFromKey(hostPrivate)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	sshPassword := cloudsync.RandomID()
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if string(p) != sshPassword {
			return nil, fmt.Errorf("bad test credential")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(hostKey)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				c, ch, req, e := ssh.NewServerConn(conn, serverConfig)
				if e != nil {
					return
				}
				defer c.Close()
				go ssh.DiscardRequests(req)
				for next := range ch {
					if next.ChannelType() != "session" {
						_ = next.Reject(ssh.UnknownChannelType, "test")
						continue
					}
					channel, requests, e := next.Accept()
					if e != nil {
						continue
					}
					for req := range requests {
						if req.Type == "exec" {
							_ = req.Reply(true, nil)
							_, _ = channel.Write([]byte("CLI_SYNC_OK\n"))
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = channel.Close()
							break
						} else {
							_ = req.Reply(false, nil)
						}
					}
				}
			}()
		}
	}()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client", "config.toml")
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	source := config.New()
	source.Servers["synthetic-live"] = &config.Server{Host: host, Port: port, User: "test", Auth: config.AuthPassword}
	_, err = vault.Data.Import(source, state.DeviceID, false)
	require.NoError(t, err)
	entry, err := vault.Data.Find("synthetic-live")
	require.NoError(t, err)
	require.NoError(t, vault.Data.SetPassword(entry.ID, sshPassword))
	path := filepath.Join(dir, "source-state.json")
	require.NoError(t, state.SaveDraft(vault, path))
	require.NoError(t, state.Sync(ctx, vault, path))
	home := filepath.Join(dir, "home")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownhosts.Line([]string{listener.Addr().String()}, hostKey.PublicKey())+"\n"), 0600))
	env := append(os.Environ(), "HOME="+home, "NO_PROXY=127.0.0.1,localhost", "SSHM_NO_UPDATE_CHECK=1")
	runTTY := func(args []string, prompts, answers []string) string {
		command := exec.CommandContext(ctx, binary, append([]string{"--config", cfgPath}, args...)...)
		command.Env = env
		terminal, e := pty.Start(command)
		require.NoError(t, e)
		defer terminal.Close()
		chunks := make(chan string, 128)
		go func() {
			defer close(chunks)
			buf := make([]byte, 4096)
			for {
				n, e := terminal.Read(buf)
				if n > 0 {
					chunks <- string(buf[:n])
				}
				if e != nil {
					return
				}
			}
		}()
		output := ""
		readUntil := func(needle string) {
			for !strings.Contains(output, needle) {
				select {
				case chunk, ok := <-chunks:
					require.True(t, ok, "CLI ended before expected prompt")
					output += chunk
				case <-ctx.Done():
					t.Fatal("CLI acceptance timed out")
				}
			}
		}
		for i, prompt := range prompts {
			readUntil(prompt)
			output = ""
			_, e = io.WriteString(terminal, answers[i]+"\n")
			require.NoError(t, e)
		}
		for chunk := range chunks {
			output += chunk
		}
		require.NoError(t, command.Wait(), "CLI acceptance command failed")
		return output
	}
	// Declining preserves the empty local list; ordinary sync subsequently fills it.
	runTTY([]string{"login", "--endpoint", endpoint, "--username", username, "--import-local"}, []string{"Account password (6+ characters):", "Vault unlock phrase (different from account password, 6+ characters):", "Sync now? [Y/n]:"}, []string{string(password), string(phrase), "n"})
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.Empty(t, cfg.Servers)
	runTTY([]string{"sync"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	// Recover an installation first touched by an older writer before its
	// independent binding index existed. The real unlocked sync must repair
	// the original alias rather than create a second suffixed connection.
	originalID := cfg.Servers["synthetic-live"].CloudEntry
	cfg.Servers["synthetic-live"].CloudEntry = ""
	cfg.Servers["synthetic-live"].CloudVault = ""
	require.NoError(t, config.Save(cfgPath, cfg))
	require.NoError(t, os.Remove(cfgPath+".cloud-bindings.json"))
	runTTY([]string{"cloud", "sync"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 1)
	require.Equal(t, originalID, cfg.Servers["synthetic-live"].CloudEntry)
	list := exec.CommandContext(ctx, binary, "--config", cfgPath, "list", "--plain", "--no-color")
	list.Env = env
	out, err := list.Output()
	require.NoError(t, err)
	require.Contains(t, string(out), "synthetic-live")
	outText := runTTY([]string{"exec", "synthetic-live", "echo CLI_SYNC_OK"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	require.Contains(t, outText, "CLI_SYNC_OK")
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.False(t, cfg.Servers["synthetic-live"].LastUsed.IsZero())
	b, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, string(b), sshPassword)
	require.NotContains(t, string(b), string(phrase))
	// Re-login accepts the default sync option without a second vault prompt.
	runTTY([]string{"cloud", "login", "--endpoint", endpoint, "--username", username}, []string{"Account password (6+ characters):", "Vault unlock phrase (different from account password, 6+ characters):", "Sync now? [Y/n]:"}, []string{string(password), string(phrase), ""})
	// Quick-add from the target: stable identity, no SSH key file or address entry.
	runTTY([]string{"cloud", "add-device", "--name", "synthetic-peer"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	runTTY([]string{"cloud", "add-device", "--name", "synthetic-peer"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	cfg, err = config.Load(cfgPath)
	require.NoError(t, err)
	require.Len(t, cfg.Servers, 2)
	require.NotEmpty(t, config.DeviceConnectionID(cfg.Servers["synthetic-peer"]))
	enable := exec.CommandContext(ctx, binary, "--config", cfgPath, "cloud", "enable", "--name", "synthetic-peer")
	enable.Env = env
	enableTTY, err := pty.Start(enable)
	require.NoError(t, err)
	defer func() { _ = enable.Process.Signal(os.Interrupt); _ = enableTTY.Close(); _ = enable.Wait() }()
	enableChunks := make(chan string, 128)
	go func() {
		defer close(enableChunks)
		buf := make([]byte, 4096)
		for {
			n, e := enableTTY.Read(buf)
			if n > 0 {
				enableChunks <- string(buf[:n])
			}
			if e != nil {
				return
			}
		}
	}()
	enableOutput := ""
	for !strings.Contains(enableOutput, "Vault unlock phrase:") {
		select {
		case text, ok := <-enableChunks:
			require.True(t, ok)
			enableOutput += text
		case <-ctx.Done():
			t.Fatal("enable prompt timed out")
		}
	}
	_, err = io.WriteString(enableTTY, string(phrase)+"\n")
	require.NoError(t, err)
	// This is a separate native client identity, not the target's token.
	second, err := cloudsync.Login(ctx, endpoint, username, "synthetic-controller", password)
	require.NoError(t, err)
	secondConfig := filepath.Join(dir, "controller", "config.toml")
	require.NoError(t, second.Save(cloudsync.StatePath(secondConfig)))
	require.Eventually(t, func() bool { agents, e := second.Agents(ctx); return e == nil && len(agents) > 0 }, 20*time.Second, 100*time.Millisecond)
	runTTY([]string{"--config", secondConfig, "cloud", "sync"}, []string{"Vault unlock phrase:"}, []string{string(phrase)})
	connected := runTTY([]string{"--config", secondConfig, "connect", "synthetic-peer"}, []string{"Vault unlock phrase:", "Encrypted device connection"}, []string{string(phrase), "printf 'SSHM_QUICK_%s_DONE\\n' VERIFIED\nexit"})
	require.Contains(t, connected, "SSHM_QUICK_VERIFIED_DONE")
	t.Log("PASS: login skip/accept, empty-device sync/list, repeat sync, real SSH exec and activity; credentials remain encrypted")
}
