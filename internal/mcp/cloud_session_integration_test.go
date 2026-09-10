package mcp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
	gssh "golang.org/x/crypto/ssh"
)

// A synthetic browser and service exercising the production signed ECDH grant,
// encrypted snapshot and HTTP client. No user account, network host or key used.
type browserFixture struct {
	server      *httptest.Server
	vault       *cloudsync.Vault
	local       *cloudsync.State
	path        string
	snapshot    cloudsync.Snapshot
	mu          sync.Mutex
	requests    map[string]cloudsync.LinkRequest
	approve     atomic.Bool
	revoked     atomic.Bool
	badGrant    atomic.Bool
	badSnapshot atomic.Bool
	reads       atomic.Int32
}

func newBrowserFixture(t *testing.T) *browserFixture {
	t.Helper()
	v, _, err := cloudsync.NewVault("mcp-test", []byte("synthetic-vault-phrase"))
	require.NoError(t, err)
	v.Data.Credentials["credential_one"] = cloudsync.Credential{Kind: "password", Password: "synthetic-ssh-password"}
	v.Data.Entries["entry_one"] = cloudsync.Entry{ID: "entry_one", Aliases: []string{"test-host"}, Server: config.Server{Host: "127.0.0.1", Port: 2222, User: "ops", Auth: config.AuthPassword}, CredentialIDs: []string{"credential_one"}}
	snap, err := v.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	snap.Revision = 1
	f := &browserFixture{vault: v, path: filepath.Join(t.TempDir(), "config.toml"), snapshot: snap, requests: map[string]cloudsync.LinkRequest{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	f.local = &cloudsync.State{URL: f.server.URL, Username: "mcp-test", DeviceID: "original_device", Token: "synthetic-original-account-token", Base: snap, Draft: snap}
	require.NoError(t, f.local.Save(cloudsync.StatePath(f.path)))
	cfg := config.New()
	target := v.Data.Entries["entry_one"].Server
	target.Auth = config.AuthCloud
	target.CloudEntry = "entry_one"
	target.CloudVault = cloudsync.InventoryIdentity(f.local)
	cfg.Servers["test-host"] = &target
	require.NoError(t, config.Save(f.path, cfg))
	t.Cleanup(func() { f.server.Close(); v.Close() })
	return f
}
func (f *browserFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/link/start":
		var request cloudsync.LinkRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		request.Expires = time.Now().Add(9 * time.Minute).UnixMilli()
		f.mu.Lock()
		f.requests[request.ID] = request
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"expires": request.Expires})
	case "/v1/link/poll":
		var input map[string]string
		json.NewDecoder(r.Body).Decode(&input)
		f.mu.Lock()
		request, ok := f.requests[input["id"]]
		f.mu.Unlock()
		if !ok || input["secret"] != request.Secret {
			w.WriteHeader(401)
			return
		}
		if !f.approve.Load() {
			io.WriteString(w, `{"status":"pending"}`)
			return
		}
		grant, signature, err := browserGrant(f.vault, &request)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if f.badGrant.Load() {
			signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "approved", "device_id": request.DeviceID, "request_expires": request.Expires, "snapshot": f.snapshot, "grant": grant, "signature": signature, "token": "synthetic-ephemeral-" + request.DeviceID, "expires": time.Now().Add(time.Hour).UnixMilli()})
	case "/v1/vault":
		f.reads.Add(1)
		if f.revoked.Load() || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer synthetic-ephemeral-") {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		f.mu.Lock()
		snap := f.snapshot
		f.mu.Unlock()
		if f.badSnapshot.Load() {
			snap.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		}
		json.NewEncoder(w).Encode(snap)
	default:
		if r.Method == http.MethodDelete {
			io.WriteString(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(404)
	}
}
func browserGrant(v *cloudsync.Vault, r *cloudsync.LinkRequest) (string, string, error) {
	enc := base64.RawURLEncoding
	pub, err := enc.DecodeString(r.PublicKey)
	if err != nil {
		return "", "", err
	}
	peer, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return "", "", err
	}
	defer cloudsync.Wipe(shared)
	derived := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte("sshm-link-v1/mcp-test/"+r.ID)), derived)
	defer cloudsync.Wipe(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	aad := []byte("sshm-link-v1\nmcp-test\n" + r.ID + "\n" + r.PublicKey)
	ciphertext := gcm.Seal(nil, nonce, v.Master, aad)
	raw, err := json.Marshal(cloudsync.LinkGrant{Version: 1, PublicKey: enc.EncodeToString(key.PublicKey().Bytes()), Nonce: enc.EncodeToString(nonce), Ciphertext: enc.EncodeToString(ciphertext)})
	if err != nil {
		return "", "", err
	}
	seed := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, v.Master, nil, []byte("sshm-v1/signature")), seed)
	defer cloudsync.Wipe(seed)
	signing := ed25519.NewKeyFromSeed(seed)
	defer cloudsync.Wipe(signing)
	grant := string(raw)
	return grant, enc.EncodeToString(ed25519.Sign(signing, cloudsync.LinkMessage("mcp-test", r, grant))), nil
}
func (f *browserFixture) session(t *testing.T) *CloudSession {
	t.Helper()
	s := NewCloudSession(f.path)
	t.Cleanup(s.Close)
	pending, err := s.Begin(context.Background())
	require.NoError(t, err)
	require.Equal(t, "pending", pending.State)
	require.NotEmpty(t, pending.Code)
	require.Equal(t, f.server.URL+"/devices", pending.ApprovalURL)
	return s
}
func (f *browserFixture) ready(t *testing.T) *CloudSession {
	t.Helper()
	f.approve.Store(true)
	s := f.session(t)
	require.Eventually(t, func() bool { return s.Status().State == "ready" }, 4*time.Second, 10*time.Millisecond)
	return s
}
func (f *browserFixture) target(t *testing.T) *config.Server {
	t.Helper()
	cfg, err := config.Load(f.path)
	require.NoError(t, err)
	return cfg.Servers["test-host"]
}

func TestBrowserApprovalEnablesCloudCredentialsWithoutExport(t *testing.T) {
	f := newBrowserFixture(t)
	before, err := os.ReadFile(cloudsync.StatePath(f.path))
	require.NoError(t, err)
	s := f.ready(t)
	target, opts, cleanup, err := s.Resolve(context.Background(), f.target(t), sshpkg.BuildOpts{Insecure: true})
	require.NoError(t, err)
	defer cleanup()
	require.Equal(t, config.AuthPassword, target.Auth)
	require.Empty(t, target.CloudEntry)
	require.Empty(t, target.CloudVault)
	require.Equal(t, "synthetic-ssh-password", opts.Password)
	require.False(t, opts.Insecure)
	require.EqualValues(t, 1, f.reads.Load())
	after, err := os.ReadFile(cloudsync.StatePath(f.path))
	require.NoError(t, err)
	require.Equal(t, before, after, "approval must not replace CLI state/token")
	output, err := maskedJSONResult(s.Status())
	require.NoError(t, err)
	for _, secret := range []string{"synthetic-ssh-password", "synthetic-ephemeral-", "synthetic-original-account-token", base64.RawURLEncoding.EncodeToString(f.vault.Master), f.snapshot.Blob} {
		require.NotContains(t, output, secret)
	}
	f.mu.Lock()
	for _, r := range f.requests {
		require.False(t, r.AllowShell)
		require.Contains(t, r.Label, "MCP credential access")
	}
	f.mu.Unlock()
}
func TestCloudSessionRevocationAndTamperFailClosed(t *testing.T) {
	for _, which := range []string{"revoked", "signature", "rollback", "changed-account", "changed-route", "wrong-vault"} {
		t.Run(which, func(t *testing.T) {
			f := newBrowserFixture(t)
			s := f.ready(t)
			target := f.target(t)
			switch which {
			case "revoked":
				f.revoked.Store(true)
			case "signature":
				f.badSnapshot.Store(true)
			case "rollback":
				f.mu.Lock()
				f.snapshot.Revision = 0
				f.mu.Unlock()
			case "changed-account":
				f.local.Token = "different-token"
				require.NoError(t, f.local.Save(cloudsync.StatePath(f.path)))
			case "changed-route":
				target.Host = "attacker.invalid"
			case "wrong-vault":
				target.CloudVault = "different-vault"
			}
			_, _, cleanup, err := s.Resolve(context.Background(), target, sshpkg.BuildOpts{})
			if cleanup != nil {
				cleanup()
			}
			require.Error(t, err)
			if which != "changed-route" && which != "wrong-vault" {
				require.Equal(t, "locked", s.Status().State)
			}
		})
	}
}

func TestAuthenticatedVaultUseRefreshesIdleOnTargetResolutionFailure(t *testing.T) {
	f := newBrowserFixture(t)
	s := f.ready(t)
	s.mu.Lock()
	authorizedAt := s.authorizedAt
	staleLastUsed := time.Now().Add(-90 * time.Minute)
	s.lastUsed = staleLastUsed
	s.mu.Unlock()
	target := f.target(t)
	target.CloudEntry = "missing_entry"

	_, _, cleanup, err := s.Resolve(context.Background(), target, sshpkg.BuildOpts{})
	if cleanup != nil {
		cleanup()
	}
	require.ErrorContains(t, err, "missing")

	s.mu.Lock()
	defer s.mu.Unlock()
	require.Greater(t, s.lastUsed, staleLastUsed.Add(time.Hour))
	require.Equal(t, authorizedAt, s.authorizedAt, "authenticated use must not extend the maximum session age")
}

func TestCloudSessionLockExpiryAndIsolation(t *testing.T) {
	f := newBrowserFixture(t)
	s := f.ready(t)
	other := NewCloudSession(f.path)
	defer other.Close()
	require.Equal(t, "locked", other.Status().State)
	s.mu.Lock()
	held := s.master
	s.lastUsed = time.Now().Add(-cloudSessionIdle)
	s.mu.Unlock()
	require.Equal(t, "locked", s.Status().State)
	require.Equal(t, make([]byte, len(held)), held)
	_, _, _, err := s.Resolve(context.Background(), f.target(t), sshpkg.BuildOpts{})
	require.ErrorContains(t, err, "cloud_unlock")
	_, err = s.Begin(context.Background())
	require.NoError(t, err)
	require.Eventually(t, func() bool { return s.Status().State == "ready" }, 4*time.Second, 10*time.Millisecond)
	s.mu.Lock()
	held = s.master
	s.authorizedAt = time.Now().Add(-cloudSessionMaximum)
	s.mu.Unlock()
	require.Equal(t, "locked", s.Status().State)
	require.Equal(t, make([]byte, len(held)), held)
}
func TestCloudSessionRejectsBadGrantAndLateApproval(t *testing.T) {
	t.Run("bad grant", func(t *testing.T) {
		f := newBrowserFixture(t)
		f.approve.Store(true)
		f.badGrant.Store(true)
		s := f.session(t)
		require.Eventually(t, func() bool { return s.Status().State == "locked" }, 4*time.Second, 10*time.Millisecond)
		require.Empty(t, s.master)
	})
	t.Run("lock pending", func(t *testing.T) {
		f := newBrowserFixture(t)
		s := f.session(t)
		s.Close()
		f.approve.Store(true)
		require.Equal(t, "locked", s.Status().State)
		_, _, _, err := s.Resolve(context.Background(), f.target(t), sshpkg.BuildOpts{})
		require.Error(t, err)
	})
}
func TestCloudCredentialsRejectAgentFallbackAndUnreviewedRoutes(t *testing.T) {
	f := newBrowserFixture(t)
	for _, kind := range []string{"missing-password", "agent", "proxy-command", "socks", "forward", "nested-jump", "conflict", "ambiguous-password"} {
		t.Run(kind, func(t *testing.T) {
			entry := f.vault.Data.Entries["entry_one"]
			data := cloudsync.NewData()
			data.Credentials = f.vault.Data.Credentials
			switch kind {
			case "missing-password":
				entry.CredentialIDs = nil
			case "agent":
				entry.Server.Auth = config.AuthAgent
				entry.CredentialIDs = nil
			case "proxy-command":
				entry.Server.ProxyCommand = "malicious-command"
			case "socks":
				entry.Server.Proxy = "socks5://127.0.0.1:1080"
			case "forward":
				entry.Server.Forwards = []string{"1234:localhost:22"}
			case "nested-jump":
				entry.Server.ProxyJump = "other"
			case "conflict":
				data.Conflicts[entry.ID] = cloudsync.Conflict{}
			case "ambiguous-password":
				data.Credentials = map[string]cloudsync.Credential{"one": {Kind: "password", Password: "one"}, "two": {Kind: "password", Password: "two"}}
				entry.CredentialIDs = []string{"one", "two"}
			}
			_, _, err := resolveCloudEntry(data, entry, sshpkg.BuildOpts{Password: "fallback"}, kind == "nested-jump")
			require.Error(t, err)
		})
	}
}

func TestBrowserApprovalToMCPExecUsesRealSSH(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	for _, name := range []string{"ALL_PROXY", "all_proxy", "SOCKS5_PROXY", "socks5_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	f := newBrowserFixture(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gssh.NewSignerFromKey(private)
	require.NoError(t, err)
	serverConfig := &gssh.ServerConfig{PasswordCallback: func(meta gssh.ConnMetadata, p []byte) (*gssh.Permissions, error) {
		if meta.User() != "ops" || string(p) != "synthetic-ssh-password" {
			return nil, errors.New("bad credentials")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, e := gssh.NewServerConn(conn, serverConfig)
		if e != nil {
			return
		}
		defer server.Close()
		go gssh.DiscardRequests(requests)
		for incoming := range channels {
			ch, reqs, e := incoming.Accept()
			if e != nil {
				return
			}
			for request := range reqs {
				if request.Type != "exec" {
					request.Reply(false, nil)
					continue
				}
				request.Reply(true, nil)
				io.WriteString(ch, "cloud-mcp-connected\n")
				ch.SendRequest("exit-status", false, gssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				break
			}
		}
	}()
	entry := f.vault.Data.Entries["entry_one"]
	entry.Server.Port = listener.Addr().(*net.TCPAddr).Port
	f.vault.Data.Entries[entry.ID] = entry
	snap, err := f.vault.Snapshot(0, cloudsync.RandomID())
	require.NoError(t, err)
	snap.Revision = 1
	f.snapshot = snap
	f.local.Base = snap
	f.local.Draft = snap
	require.NoError(t, f.local.Save(cloudsync.StatePath(f.path)))
	cfg, err := config.Load(f.path)
	require.NoError(t, err)
	cfg.Servers["test-host"].Port = entry.Server.Port
	require.NoError(t, config.Save(f.path, cfg))
	session := f.ready(t)
	deps := Deps{ConfigPath: f.path, AuditPath: filepath.Join(t.TempDir(), "audit.log"), AllowWrite: true, CloudSession: session}
	result, err := handleExec(context.Background(), deps, map[string]any{"alias": "test-host", "command": "hostname", "reason": "synthetic integration test", "raw_environment": true})
	require.NoError(t, err)
	text, err := maskedJSONResult(result)
	require.NoError(t, err)
	require.Contains(t, text, "cloud-mcp-connected")
	require.NotContains(t, text, "synthetic-ssh-password")
	audit, err := os.ReadFile(deps.AuditPath)
	require.NoError(t, err)
	require.NotContains(t, string(audit), "synthetic-ssh-password")
	require.NotContains(t, string(audit), "synthetic-ephemeral-")
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH test connection did not close")
	}
	session.Close()
	result, err = handleExec(context.Background(), deps, map[string]any{"alias": "test-host", "command": "hostname", "reason": "verify lock blocks access", "raw_environment": true})
	require.NoError(t, err)
	text, err = maskedJSONResult(result)
	require.NoError(t, err)
	require.Contains(t, text, "cloud_unlock")
	require.NotContains(t, text, "cloud-mcp-connected")
}
