package cloudagent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEncryptedRelayRunsNativePTYAndStopsOnDisconnect(t *testing.T) {
	v, _, e := cloudsync.NewVault("agent-test", []byte("test-unlock"))
	require.NoError(t, e)
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, e := websocket.Accept(w, r, nil)
		if e != nil {
			result <- e
			return
		}
		defer ws.CloseNow()
		run := func() error {
			epoch := r.URL.Query().Get("epoch")
			session := cloudsync.RandomID()
			req := cloudsync.ShellOpen{Type: "open", Device: "test_device", Epoch: epoch, Session: session, Expires: time.Now().Add(time.Minute).UnixMilli()}
			seed := make([]byte, 32)
			io.ReadFull(hkdf.New(sha256.New, v.Master, nil, []byte("sshm-v1/signature")), seed)
			req.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(req.Message("agent-test"))))
			b, _ := json.Marshal(req)
			if e = ws.Write(ctx, websocket.MessageText, b); e != nil {
				return e
			}
			send, _ := cloudsync.NewShellCipher(v.Master, "agent-test", "test_device", epoch, session, "c2a")
			recv, _ := cloudsync.NewShellCipher(v.Master, "agent-test", "test_device", epoch, session, "a2c")
			sent := false
			output := ""
			for {
				_, b, e := ws.Read(ctx)
				if e != nil {
					return e
				}
				if strings.Contains(string(b), "SSHM_PTY") {
					return fmt.Errorf("plaintext in relay frame")
				}
				var frame cloudsync.ShellFrame
				if json.Unmarshal(b, &frame) != nil {
					return fmt.Errorf("invalid frame")
				}
				p, e := recv.Open(frame)
				if e != nil {
					return e
				}
				if p.Type == "ready" && !sent {
					command := "printf 'SSHM_PTY_%s_DONE\\n' PASS\r"
					if runtime.GOOS == "windows" {
						command = "Write-Output ('SSHM_PTY_' + 'PASS_DONE')\r"
					}
					f, e := send.Seal(cloudsync.ShellPayload{Type: "input", Data: base64.RawURLEncoding.EncodeToString([]byte(command))})
					if e != nil {
						return e
					}
					b, _ = json.Marshal(f)
					if e = ws.Write(ctx, websocket.MessageText, b); e != nil {
						return e
					}
					sent = true
				}
				if p.Type == "output" {
					raw, e := base64.RawURLEncoding.DecodeString(p.Data)
					if e != nil {
						return e
					}
					output += string(raw)
					if strings.Contains(output, "SSHM_PTY_PASS_DONE") {
						return nil
					}
				}
			}
		}
		result <- run()
	}))
	defer server.Close()
	state := &cloudsync.State{URL: server.URL, Username: "agent-test", DeviceID: "test_device", Token: strings.Repeat("a", 43)}
	done := make(chan error, 1)
	go func() { done <- connect(ctx, state, v) }()
	require.NoError(t, <-result)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop after transport disconnect")
	}
}
