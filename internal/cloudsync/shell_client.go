package cloudsync

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type AgentCapability struct {
	RuntimeVersion string `json:"runtime_version,omitempty"`
	Continuous     bool   `json:"continuous"`
	DeviceID       string `json:"device_id"`
	Epoch          string `json:"epoch"`
}

func (s *State) Agents(ctx context.Context) ([]AgentCapability, error) {
	var out struct {
		Agents []AgentCapability `json:"agents"`
	}
	err := s.Request(ctx, "GET", "/v1/agents", nil, &out)
	return out.Agents, err
}
func (v *Vault) SignShell(r *ShellOpen, user string) {
	p := v.private()
	defer Wipe(p)
	r.Signature = encoding.EncodeToString(ed25519.Sign(p, []byte(r.Message(user))))
}

type DeviceTerminal struct {
	conn       *websocket.Conn
	send, recv *ShellCipher
	mu         sync.Mutex
	cancel     context.CancelFunc
	ctx        context.Context
}

// OpenDeviceTerminal requires the unlocked vault, not only the account token.
// The relay and target verify a signed, expiring connection request; all terminal frames
// are authenticated ciphertext with independent monotonic direction counters.
func OpenDeviceTerminal(ctx context.Context, s *State, v *Vault, device string) (*DeviceTerminal, error) {
	if err := ValidateURL(s.URL); err != nil {
		return nil, err
	}
	agents, err := s.Agents(ctx)
	if err != nil {
		return nil, err
	}
	epoch := ""
	for _, a := range agents {
		if a.DeviceID == device {
			if !a.Continuous {
				return nil, errors.New("target agent needs an update for continuous terminals: on the target run sshm update, stop the old agent, then sshm cloud enable")
			}
			epoch = a.Epoch
			break
		}
	}
	if epoch == "" {
		return nil, errors.New("device is offline or connections are disabled; run sshm cloud enable on the target")
	}
	r := ShellOpen{Lifetime: "connection", Type: "open", Device: device, Epoch: epoch, Session: RandomID(), Expires: time.Now().Add(2 * time.Minute).UnixMilli()}
	v.SignShell(&r, s.Username)
	ctx, cancel := context.WithCancel(ctx)
	u, _ := url.Parse(strings.TrimRight(s.URL, "/") + "/v1/relay")
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	q := u.Query()
	q.Set("role", "client")
	q.Set("session", r.Session)
	u.RawQuery = q.Encode()
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	conn, response, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + s.Token}, "X-SSHM-Account": []string{s.Username}}})
	if err != nil {
		cancel()
		if response != nil {
			return nil, &APIError{Status: response.StatusCode, Code: "device_relay_unavailable"}
		}
		return nil, errors.New("device relay unavailable")
	}
	t := &DeviceTerminal{conn: conn, cancel: cancel, ctx: ctx}
	conn.SetReadLimit(65536)
	t.send, err = NewShellCipher(v.Master, s.Username, device, epoch, r.Session, "c2a")
	if err != nil {
		t.Close()
		return nil, err
	}
	t.recv, err = NewShellCipher(v.Master, s.Username, device, epoch, r.Session, "a2c")
	if err != nil {
		t.Close()
		return nil, err
	}
	if err = t.write(r); err != nil {
		t.Close()
		return nil, err
	}
	handshake, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	payload, err := t.Receive(handshake)
	if err != nil || payload.Type != "ready" {
		t.Close()
		return nil, errors.New("device did not complete the encrypted terminal handshake")
	}
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if t.write(map[string]string{"type": "ping"}) != nil {
					t.Close()
					return
				}
			}
		}
	}()
	return t, nil
}
func (t *DeviceTerminal) write(v any) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writeLocked(v)
}
func (t *DeviceTerminal) writeLocked(v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer cancel()
	return t.conn.Write(ctx, websocket.MessageText, b)
}
func (t *DeviceTerminal) Send(p ShellPayload) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, e := t.send.Seal(p)
	if e != nil {
		return e
	}
	return t.writeLocked(f)
}
func (t *DeviceTerminal) Receive(ctx context.Context) (ShellPayload, error) {
	for {
		readCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, b, e := t.conn.Read(readCtx)
		cancel()
		if e != nil {
			return ShellPayload{}, e
		}
		var m struct{ Type string }
		if json.Unmarshal(b, &m) != nil {
			return ShellPayload{}, errors.New("invalid relay message")
		}
		if m.Type == "pong" {
			continue
		}
		if m.Type == "close" {
			return ShellPayload{Type: "closed"}, nil
		}
		var f ShellFrame
		if json.Unmarshal(b, &f) != nil {
			return ShellPayload{}, errors.New("invalid encrypted frame")
		}
		return t.recv.Open(f)
	}
}
func (t *DeviceTerminal) Close() {
	if t == nil {
		return
	}
	t.cancel()
	_ = t.conn.CloseNow()
}
