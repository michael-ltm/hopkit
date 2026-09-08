package cloudagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testSSH(t *testing.T) (string, int, <-chan struct{}) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	signer, e := gssh.NewSignerFromKey(key)
	require.NoError(t, e)
	cfg := &gssh.ServerConfig{PasswordCallback: func(c gssh.ConnMetadata, b []byte) (*gssh.Permissions, error) {
		if c.User() == "fixture" && string(b) == "test-secret" {
			return nil, nil
		}
		return nil, io.EOF
	}}
	cfg.AddHostKey(signer)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	t.Cleanup(func() { listener.Close() })
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		server, chans, reqs, e := gssh.NewServerConn(conn, cfg)
		if e != nil {
			return
		}
		defer server.Close()
		go gssh.DiscardRequests(reqs)
		for incoming := range chans {
			if incoming.ChannelType() != "session" {
				incoming.Reject(gssh.UnknownChannelType, "session only")
				continue
			}
			ch, requests, e := incoming.Accept()
			if e != nil {
				return
			}
			go func() {
				defer ch.Close()
				for r := range requests {
					switch r.Type {
					case "pty-req", "window-change":
						r.Reply(true, nil)
					case "shell":
						r.Reply(true, nil)
						go func() {
							buf := make([]byte, 1024)
							for {
								n, e := ch.Read(buf)
								if n > 0 {
									ch.Write([]byte("TARGET:" + string(buf[:n])))
								}
								if e != nil {
									return
								}
							}
						}()
					default:
						r.Reply(false, nil)
					}
				}
			}()
		}
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	return host, n, closed
}
func TestTargetUsesVerifiedVaultCredentialAndRemotePTY(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	host, port, closed := testSSH(t)
	v, _, e := cloudsync.NewVault("target-test", []byte("test-unlock"))
	require.NoError(t, e)
	defer v.Close()
	cfg := config.New()
	cfg.Servers["fixture"] = &config.Server{Host: host, Port: port, User: "fixture", Auth: config.AuthPassword}
	_, e = v.Data.Import(cfg, "device-test", false)
	require.NoError(t, e)
	var id string
	for k := range v.Data.Entries {
		id = k
	}
	require.NoError(t, v.Data.SetPassword(id, "test-secret"))
	snap, e := v.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, e)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vault" {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(snap)
	}))
	defer api.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state := &cloudsync.State{URL: api.URL, Username: "target-test"}
	tty, e := openTarget(ctx, state, v.Master, filepath.Join(home, "absent.toml"), cloudsync.ShellPayload{Target: id, Cols: 90, Rows: 28})
	require.NoError(t, e)
	defer tty.Close()
	require.NoError(t, tty.Resize(101, 32))
	_, e = tty.Write([]byte("hello\n"))
	require.NoError(t, e)
	buf := make([]byte, 1024)
	n, e := tty.Read(buf)
	require.NoError(t, e)
	require.Contains(t, string(buf[:n]), "TARGET:hello")
	tty.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("target SSH session leaked")
	}
	v.Data.Deleted[id] = true
	snap, e = v.Snapshot(1, cloudsync.RandomID())
	require.NoError(t, e)
	_, e = openTarget(ctx, state, v.Master, "", cloudsync.ShellPayload{Target: id, Cols: 90, Rows: 28})
	require.EqualError(t, e, "target_removed")
}
func TestTargetRejectsForeignRoutesChangedAliasesAndAmbiguousPasswords(t *testing.T) {
	s := config.Server{Host: "example.invalid", Port: 22, User: "test", Auth: config.AuthPassword, ProxyCommand: "do-not-run"}
	entry := cloudsync.Entry{ID: cloudsync.EntryID(s), Server: s, CredentialIDs: []string{"one", "two"}}
	data := cloudsync.NewData()
	data.Credentials["one"] = cloudsync.Credential{Kind: "password", Password: "one"}
	data.Credentials["two"] = cloudsync.Credential{Kind: "password", Password: "two"}
	cfg := config.New()
	wrong := s
	wrong.Host = "changed.invalid"
	cfg.Servers["test"] = &wrong
	_, _, e := targetOptions(data, entry, cfg, "", " ")
	require.EqualError(t, e, "source_device_required")
	cfg.Servers["test"] = &s
	_, _, e = targetOptions(data, entry, cfg, "", "")
	require.EqualError(t, e, "choose_credential")
	_, opts, e := targetOptions(data, entry, cfg, "", "one")
	require.NoError(t, e)
	require.Equal(t, "one", opts.Password)
	_, _, e = targetOptions(data, entry, cfg, "", "missing")
	require.EqualError(t, e, "invalid_credential")
	require.NotContains(t, targetError(io.EOF), "EOF")
	require.Equal(t, "connection_failed", targetError(io.EOF))
	require.False(t, strings.Contains(targetError(io.EOF), s.Host))
}

func TestEncryptedRelaySelectsRemoteTargetAndClosesSSH(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	host, port, sshClosed := testSSH(t)
	v, _, e := cloudsync.NewVault("encrypted-target", []byte("test-unlock"))
	require.NoError(t, e)
	defer v.Close()
	cfg := config.New()
	cfg.Servers["remote"] = &config.Server{Host: host, Port: port, User: "fixture", Auth: config.AuthPassword}
	_, e = v.Data.Import(cfg, "target_device", false)
	require.NoError(t, e)
	var id string
	for k := range v.Data.Entries {
		id = k
	}
	require.NoError(t, v.Data.SetPassword(id, "test-secret"))
	snap, e := v.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result := make(chan error, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vault" {
			json.NewEncoder(w).Encode(snap)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			result <- err
			return
		}
		defer ws.CloseNow()
		result <- func() error {
			epoch := r.URL.Query().Get("epoch")
			session := cloudsync.RandomID()
			request := cloudsync.ShellOpen{Type: "open", Mode: "ssh", Device: "target_device", Epoch: epoch, Session: session, Expires: time.Now().Add(time.Minute).UnixMilli()}
			seed := make([]byte, 32)
			io.ReadFull(hkdf.New(sha256.New, v.Master, nil, []byte("sshm-v1/signature")), seed)
			request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(request.Message("encrypted-target"))))
			b, _ := json.Marshal(request)
			if err = ws.Write(ctx, websocket.MessageText, b); err != nil {
				return err
			}
			send, _ := cloudsync.NewShellCipher(v.Master, "encrypted-target", "target_device", epoch, session, "c2a")
			recv, _ := cloudsync.NewShellCipher(v.Master, "encrypted-target", "target_device", epoch, session, "a2c")
			selected, ready := false, false
			for {
				_, raw, err := ws.Read(ctx)
				if err != nil {
					return err
				}
				if strings.Contains(string(raw), id) || strings.Contains(string(raw), "test-secret") {
					return fmt.Errorf("plaintext target information in relay")
				}
				var frame cloudsync.ShellFrame
				if err = json.Unmarshal(raw, &frame); err != nil {
					return err
				}
				p, err := recv.Open(frame)
				if err != nil {
					return err
				}
				var reply cloudsync.ShellPayload
				switch p.Type {
				case "select":
					if selected {
						return fmt.Errorf("duplicate selection")
					}
					selected = true
					reply = cloudsync.ShellPayload{Type: "connect", Target: id, Cols: 100, Rows: 30}
				case "ready":
					if !selected {
						return fmt.Errorf("local shell started before target selection")
					}
					ready = true
					reply = cloudsync.ShellPayload{Type: "input", Data: base64.RawURLEncoding.EncodeToString([]byte("remote-proof\n"))}
				case "output":
					if !ready {
						return fmt.Errorf("premature output")
					}
					decoded, _ := base64.RawURLEncoding.DecodeString(p.Data)
					if strings.Contains(string(decoded), "TARGET:remote-proof") {
						return nil
					}
					continue
				default:
					return fmt.Errorf("unexpected encrypted response %s %s", p.Type, p.Data)
				}
				frame, err = send.Seal(reply)
				if err != nil {
					return err
				}
				b, _ = json.Marshal(frame)
				if err = ws.Write(ctx, websocket.MessageText, b); err != nil {
					return err
				}
			}
		}()
	}))
	defer api.Close()
	done := make(chan error, 1)
	go func() {
		done <- connectPath(ctx, &cloudsync.State{URL: api.URL, Username: "encrypted-target", DeviceID: "target_device"}, v, filepath.Join(home, "absent.toml"))
	}()
	require.NoError(t, <-result)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
	}
	select {
	case <-sshClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("target leaked")
	}
}
