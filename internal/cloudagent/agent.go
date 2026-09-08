// Package cloudagent runs an explicitly enabled outbound encrypted terminal.
package cloudagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type session struct {
	mu              sync.Mutex
	sendMu          sync.Mutex
	pty             terminal
	recv, send      *cloudsync.ShellCipher
	cancel          context.CancelFunc
	ctx             context.Context
	started, closed bool
	input           chan cloudsync.ShellPayload
}

func (x *session) close() {
	x.mu.Lock()
	x.closed = true
	tty := x.pty
	x.mu.Unlock()
	x.cancel()
	if tty != nil {
		tty.Close()
	}
}
func (x *session) attach(tty terminal) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		tty.Close()
		return false
	}
	x.pty = tty
	return true
}
func (x *session) payload(p cloudsync.ShellPayload, send func(any) error) error {
	x.sendMu.Lock()
	defer x.sendMu.Unlock()
	f, e := x.send.Seal(p)
	if e != nil {
		return e
	}
	return send(f)
}

// Serve reconnects the transport only. Revoked sessions stop the process. The
// caller retains the master in memory and owns the periodic encrypted sync.
func Serve(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault) error {
	return ServeTargets(ctx, s, v, config.ConfigPath())
}

func ServeTargets(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, path string) error {
	return servePath(ctx, s, v, 5*time.Second, path)
}
func serve(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, retryDelay time.Duration) error {
	return servePath(ctx, s, v, retryDelay, config.ConfigPath())
}
func servePath(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, retryDelay time.Duration, path string) error {
	if err := cloudsync.ValidateURL(s.URL); err != nil {
		return err
	}
	for {
		err := connectPath(ctx, s, v, path)
		if ctx.Err() != nil {
			return nil
		}
		var api *cloudsync.APIError
		if errors.As(err, &api) && (api.Status == 401 || api.Status == 403) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retryDelay):
		}
	}
}
func connect(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault) error {
	return connectPath(ctx, s, v, config.ConfigPath())
}
func connectPath(ctx context.Context, s *cloudsync.State, v *cloudsync.Vault, path string) error {
	epoch := cloudsync.RandomID()
	u, _ := url.Parse(strings.TrimRight(s.URL, "/") + "/v1/relay")
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	q := u.Query()
	q.Set("role", "agent")
	q.Set("protocol", "3")
	q.Set("version", s.RuntimeVersion)
	q.Set("target", "ssh")
	q.Set("epoch", epoch)
	u.RawQuery = q.Encode()
	headers := http.Header{"Authorization": []string{"Bearer " + s.Token}, "X-SSHM-Account": []string{s.Username}}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	conn, res, e := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: headers, HTTPClient: client})
	if e != nil {
		if res != nil {
			return &cloudsync.APIError{Status: res.StatusCode, Code: "relay_unavailable"}
		}
		return errors.New("relay unavailable")
	}
	defer conn.CloseNow()
	conn.SetReadLimit(65536)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var sendMu sync.Mutex
	send := func(m any) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		b, _ := json.Marshal(m)
		writeCtx, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		return conn.Write(writeCtx, websocket.MessageText, b)
	}
	sessions := map[string]*session{}
	seen := map[string]int64{}
	var mu sync.Mutex
	closeSession := func(id string) {
		mu.Lock()
		x := sessions[id]
		delete(sessions, id)
		mu.Unlock()
		if x != nil {
			x.close()
		}
	}
	defer func() {
		mu.Lock()
		for _, x := range sessions {
			x.close()
		}
		mu.Unlock()
	}()
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if send(map[string]string{"type": "ping"}) != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		readCtx, readDone := context.WithTimeout(ctx, 90*time.Second)
		_, b, e := conn.Read(readCtx)
		readDone()
		if e != nil {
			return e
		}
		var m struct{ Type, Session string }
		if json.Unmarshal(b, &m) != nil {
			return errors.New("invalid relay message")
		}
		switch m.Type {
		case "pong":
		case "open":
			var r cloudsync.ShellOpen
			if json.Unmarshal(b, &r) != nil || !v.VerifyShell(r, s.Username, s.DeviceID, epoch) {
				continue
			}
			mu.Lock()
			for id, expires := range seen {
				if expires <= time.Now().UnixMilli() {
					delete(seen, id)
				}
			}
			busy := len(sessions) >= 2 || sessions[r.Session] != nil || seen[r.Session] != 0 || len(seen) >= 256
			mu.Unlock()
			if busy {
				_ = send(map[string]string{"type": "close", "session": r.Session})
				continue
			}
			sessionCtx, stop := terminalContext(ctx, r)
			recv, _ := cloudsync.NewShellCipher(v.Master, s.Username, s.DeviceID, epoch, r.Session, "c2a")
			out, _ := cloudsync.NewShellCipher(v.Master, s.Username, s.DeviceID, epoch, r.Session, "a2c")
			x := &session{recv: recv, send: out, cancel: stop, ctx: sessionCtx, input: make(chan cloudsync.ShellPayload, 32), started: r.Mode != "ssh"}
			mu.Lock()
			seen[r.Session] = r.Expires
			sessions[r.Session] = x
			mu.Unlock()
			go func() { <-sessionCtx.Done(); closeSession(r.Session) }()
			go func() {
				select {
				case <-sessionCtx.Done():
					return
				case <-time.After(30 * time.Second):
					x.mu.Lock()
					ready := x.pty != nil
					x.mu.Unlock()
					if !ready {
						closeSession(r.Session)
					}
				}
			}()
			if r.Mode == "ssh" {
				if x.payload(cloudsync.ShellPayload{Type: "select"}, send) != nil {
					closeSession(r.Session)
				}
			} else {
				go func() {
					tty, err := startTerminal(100, 30)
					if err != nil {
						closeSession(r.Session)
						_ = send(map[string]string{"type": "close", "session": r.Session})
						return
					}
					runTerminal(x, r.Session, tty, send, closeSession)
				}()
			}

		case "frame":
			var f cloudsync.ShellFrame
			if json.Unmarshal(b, &f) != nil {
				return errors.New("invalid frame")
			}
			mu.Lock()
			x := sessions[f.Session]
			mu.Unlock()
			if x == nil {
				continue
			}
			p, e := x.recv.Open(f)
			if e != nil {
				closeSession(f.Session)
				continue
			}
			if p.Type == "connect" {
				x.mu.Lock()
				allowed := !x.started && !x.closed
				x.started = true
				x.mu.Unlock()
				if !allowed {
					closeSession(f.Session)
					continue
				}
				master := append([]byte(nil), v.Master...)
				go func() {
					defer cloudsync.Wipe(master)
					dialCtx, done := context.WithTimeout(x.ctx, 25*time.Second)
					defer done()
					tty, err := openTarget(dialCtx, s, master, path, p)
					if err != nil {
						_ = x.payload(cloudsync.ShellPayload{Type: "error", Data: targetError(err)}, send)
						closeSession(f.Session)
						_ = send(map[string]string{"type": "close", "session": f.Session})
						return
					}
					runTerminal(x, f.Session, tty, send, closeSession)
				}()
				continue
			}
			x.mu.Lock()
			ready := x.pty != nil
			x.mu.Unlock()
			if !ready {
				closeSession(f.Session)
				continue
			}
			select {
			case x.input <- p:
			default:
				closeSession(f.Session)
			}

		case "close":
			closeSession(m.Session)
		default:
			return errors.New("invalid relay message")
		}
	}
}

func runTerminal(x *session, id string, tty terminal, send func(any) error, closeSession func(string)) {
	if !x.attach(tty) {
		return
	}
	defer closeSession(id)
	defer send(map[string]string{"type": "close", "session": id})
	if x.payload(cloudsync.ShellPayload{Type: "ready"}, send) != nil {
		return
	}
	go func() {
		for {
			select {
			case <-x.ctx.Done():
				return
			case p := <-x.input:
				var err error
				switch p.Type {
				case "input":
					var raw []byte
					raw, err = base64.RawURLEncoding.DecodeString(p.Data)
					if err == nil && len(raw) <= 8192 {
						_, err = tty.Write(raw)
					} else {
						err = errors.New("invalid input")
					}
					cloudsync.Wipe(raw)
				case "resize":
					if validSize(p.Cols, p.Rows) {
						err = tty.Resize(p.Cols, p.Rows)
					} else {
						err = errors.New("invalid resize")
					}
				default:
					err = errors.New("invalid terminal message")
				}
				if err != nil {
					closeSession(id)
					return
				}
			}
		}
	}()
	buf := make([]byte, 8192)
	defer cloudsync.Wipe(buf)
	for {
		n, err := tty.Read(buf)
		if n > 0 {
			if x.payload(cloudsync.ShellPayload{Type: "output", Data: base64.RawURLEncoding.EncodeToString(buf[:n])}, send) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
func targetError(err error) string {
	switch err.Error() {
	case "invalid_target", "vault_unavailable", "target_removed", "target_conflict", "source_device_required", "choose_credential", "invalid_credential", "key_locked", "password_unavailable", "pty_unavailable", "ssh_credential", "ssh_authentication", "ssh_timeout", "ssh_host_key", "ssh_connection", "ssh_refused", "ssh_dns", "ssh_unknown":
		return err.Error()
	}
	return "connection_failed"
}

// v3 expires is an admission deadline. Established sessions live until the
// transport closes or authorization is revoked; legacy opens retain their cap.
func terminalContext(ctx context.Context, r cloudsync.ShellOpen) (context.Context, context.CancelFunc) {
	if r.Lifetime == "connection" {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, time.UnixMilli(r.Expires))
}
