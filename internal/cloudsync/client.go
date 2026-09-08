package cloudsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/michael-ltm/sshm/internal/inventory"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const DefaultURL = "https://sshm.yunmini.net"

type State struct {
	// Process-only metadata; never persist a runtime version in the account file.
	RuntimeVersion string    `json:"-"`
	URL            string    `json:"url"`
	Username       string    `json:"username"`
	DeviceID       string    `json:"device_id"`
	Token          string    `json:"token,omitempty"`
	Expires        int64     `json:"expires"`
	Base           Snapshot  `json:"base"`
	Draft          Snapshot  `json:"draft"`
	Dirty          bool      `json:"dirty"`
	Pending        *Snapshot `json:"pending,omitempty"`
}
type LoginResult struct {
	Token    string   `json:"token"`
	DeviceID string   `json:"device_id"`
	Expires  int64    `json:"expires"`
	Snapshot Snapshot `json:"snapshot"`
}
type Device struct {
	ID                 string   `json:"id"`
	Label              string   `json:"label"`
	Expires            int64    `json:"expires"`
	Created            int64    `json:"created"`
	Kind               string   `json:"kind"`
	Platform           string   `json:"platform"`
	Version            string   `json:"version"`
	InstalledVersion   string   `json:"installed_version,omitempty"`
	InstalledCheckedAt int64    `json:"installed_checked_at,omitempty"`
	LastSeen           int64    `json:"last_seen"`
	Group              string   `json:"group"`
	Tags               []string `json:"tags"`
	Note               string   `json:"note"`
}
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloud request failed (HTTP %d, %s)", e.Status, e.Code)
}
func StatePath(configPath string) string { return configPath + ".cloud/state.json" }
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer Wipe(b)
	var s State
	if len(b) > 10*MaxBlob || json.Unmarshal(b, &s) != nil || !ValidAccount(s.Username) {
		return nil, errors.New("invalid cloud state")
	}
	return &s, nil
}
func WritePrivate(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cloud-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// Protect the new file before any token or encrypted credential bytes are written.
	if err = protectPrivateFile(f.Name()); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func (s *State) Save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	defer Wipe(b)
	return WritePrivate(path, b)
}
func (s *State) SaveDraft(v *Vault, path string) error {
	if s.Pending != nil {
		return errors.New("retry cloud sync before editing a pending upload; the original operation is preserved")
	}
	snap, err := v.Snapshot(s.Base.Revision, RandomID())
	if err != nil {
		return err
	}
	s.Draft = snap
	s.Dirty = true
	s.Pending = nil
	return s.Save(path)
}
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("cloud endpoint must be an HTTPS origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return errors.New("HTTPS is required except for localhost tests")
	}
	if u.Hostname() == "" {
		return errors.New("cloud hostname is required")
	}
	return nil
}
func (s *State) Request(ctx context.Context, method, path string, input, output any) error {
	if err := ValidateURL(s.URL); err != nil {
		return err
	}
	var b []byte
	var err error
	if input != nil {
		b, err = json.Marshal(input)
		if err != nil {
			return err
		}
	} else if method != "GET" {
		b = []byte("{}")
	}
	defer Wipe(b)
	if len(b) > 3*1024*1024 {
		return errors.New("cloud request exceeds limit")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid cloud request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SSHM-Account", s.Username)
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("cloud redirects are not permitted") }}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("cloud network unavailable; local data retained")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4*MaxBlob+1))
	if err != nil || len(raw) > 4*MaxBlob {
		return errors.New("invalid or oversized cloud response")
	}
	defer Wipe(raw)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if !regexpCode(e.Error) {
			e.Error = "request_failed"
		}
		return &APIError{Status: res.StatusCode, Code: e.Error}
	}
	if output != nil && json.Unmarshal(raw, output) != nil {
		return errors.New("invalid cloud response")
	}
	return nil
}
func regexpCode(s string) bool {
	if s == "" || len(s) > 60 {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			if r != '_' {
				return false
			}
		}
	}
	return true
}
func Register(ctx context.Context, endpoint, user, label string, password []byte, v *Vault, recovery string) (*State, error) {
	snap, err := v.Snapshot(0, RandomID())
	if err != nil {
		return nil, err
	}
	auth, err := RecoveryAuth(recovery)
	if err != nil {
		return nil, err
	}
	s := &State{URL: endpoint, Username: user, DeviceID: RandomID()}
	var out LoginResult
	in := map[string]any{"password": string(password), "label": label, "device_id": s.DeviceID, "root_public": snap.RootPublic, "operation_id": snap.OperationID, "blob": snap.Blob, "signature": snap.Signature, "recovery_auth": auth}
	if err = s.Request(ctx, "POST", "/v1/register", in, &out); err != nil {
		return nil, err
	}
	if out.Snapshot.Blob != snap.Blob || out.Snapshot.Signature != snap.Signature || out.Snapshot.Revision != 1 {
		return nil, errors.New("registration response authentication failed")
	}
	s.Token = out.Token
	s.Expires = out.Expires
	s.Base = out.Snapshot
	s.Draft = out.Snapshot
	return s, nil
}
func Login(ctx context.Context, endpoint, user, label string, password []byte) (*State, error) {
	return LoginDevice(ctx, endpoint, user, label, password, RandomID())
}
func LoginDevice(ctx context.Context, endpoint, user, label string, password []byte, device string) (*State, error) {
	s := &State{URL: endpoint, Username: user, DeviceID: device}
	var out LoginResult
	if err := s.Request(ctx, "POST", "/v1/login", map[string]any{"password": string(password), "label": label, "device_id": s.DeviceID}, &out); err != nil {
		return nil, err
	}
	s.Token = out.Token
	s.Expires = out.Expires
	s.Base = out.Snapshot
	s.Draft = out.Snapshot
	return s, nil
}

func (s *State) Heartbeat(ctx context.Context, version string) error {
	_ = s.ReportInstalledVersion(ctx)
	return s.Request(ctx, "POST", "/v1/heartbeat", map[string]string{"platform": runtime.GOOS, "version": version}, nil)
}

func (s *State) HeartbeatResources(ctx context.Context, version string, hardware *inventory.Snapshot) error {
	_ = s.ReportInstalledVersion(ctx)
	return s.Request(ctx, "POST", "/v1/heartbeat", map[string]any{"platform": runtime.GOOS, "version": version, "hardware": inventory.PublicResources(hardware)}, nil)
}

// Sync keeps a persisted pending request for exact idempotent retry after a lost
// response. A failed upload never erases the encrypted local draft.
func (s *State) Sync(ctx context.Context, v *Vault, path string) error {
	if s.Token == "" {
		return errors.New("login required for cloud sync")
	}
	if s.Pending != nil {
		pending := *s.Pending
		var out Snapshot
		er := s.Request(ctx, "PUT", "/v1/vault", pending, &out)
		if er == nil {
			verified, e := UnlockMaster(s.Username, out, v.Master)
			if e != nil {
				return e
			}
			defer verified.Close()
			if out.Blob != pending.Blob || out.Signature != pending.Signature {
				return errors.New("pending operation mismatch")
			}
			v.Data.Close()
			v.Data = verified.Data
			v.Envelope = verified.Envelope
			verified.Data = NewData() // ownership transferred; deferred Close must not wipe it
			s.Base = out
			s.Draft = out
			s.Pending = nil
			s.Dirty = false
			return s.Save(path)
		}
		var api *APIError
		if !errors.As(er, &api) || api.Status != 409 {
			return er
		}
		s.Pending = nil
	}
	var remote Snapshot
	if err := s.Request(ctx, "GET", "/v1/vault", nil, &remote); err != nil {
		return err
	}
	if remote.Revision < s.Base.Revision {
		return errors.New("cloud revision rollback detected")
	}
	rv, err := UnlockMaster(s.Username, remote, v.Master)
	if err != nil {
		return errors.New("cloud vault authentication failed; it may have been rekeyed on another device")
	}
	defer rv.Close()
	if remote.Revision == s.Base.Revision && (remote.Blob != s.Base.Blob || remote.Signature != s.Base.Signature) {
		return errors.New("cloud history was replaced")
	}
	if !s.Dirty {
		v.Data.Close()
		v.Data = rv.Data
		v.Envelope = rv.Envelope
		rv.Data = NewData()
		s.Base = remote
		s.Draft = remote
		return s.Save(path)
	}
	bv, err := UnlockMaster(s.Username, s.Base, v.Master)
	if err != nil {
		return err
	}
	defer bv.Close()
	merged, err := Merge(bv.Data, v.Data, rv.Data)
	if err != nil {
		return err
	}
	v.Data.Close()
	v.Data = merged
	request, err := v.Snapshot(remote.Revision, RandomID())
	if err != nil {
		return err
	}
	s.Draft = request
	s.Pending = &request
	if err = s.Save(path); err != nil {
		return err
	}
	var out Snapshot
	if err = s.Request(ctx, "PUT", "/v1/vault", request, &out); err != nil {
		return err
	}
	if out.Blob != request.Blob || out.Signature != request.Signature || out.Revision != remote.Revision+1 {
		return errors.New("cloud commit acknowledgement mismatch")
	}
	s.Base = out
	s.Draft = out
	s.Pending = nil
	s.Dirty = false
	return s.Save(path)
}

// SyncRetry handles a short burst of concurrent signed commits. Each retry uses
// Sync's persisted pending operation and three-way merge, never a blind overwrite.
func (s *State) SyncRetry(ctx context.Context, v *Vault, path string) error {
	for attempt := 0; ; attempt++ {
		err := s.Sync(ctx, v, path)
		var api *APIError
		if err == nil || attempt >= 4 || !errors.As(err, &api) || api.Status != 409 {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
