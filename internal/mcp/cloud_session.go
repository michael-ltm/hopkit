package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
)

const cloudSessionIdle = 2 * time.Hour
const cloudSessionMaximum = 12 * time.Hour
const cloudSessionPolicyLimit = 30 * 24 * time.Hour

// CloudSessionPolicy controls how long an approved MCP process can keep cloud
// credentials in memory. The cloud token expiry remains an independent upper
// bound.
type CloudSessionPolicy struct {
	IdleTimeout time.Duration
	MaximumAge  time.Duration
}

func DefaultCloudSessionPolicy() CloudSessionPolicy {
	return CloudSessionPolicy{IdleTimeout: cloudSessionIdle, MaximumAge: cloudSessionMaximum}
}

func (p CloudSessionPolicy) Validate() error {
	if p.IdleTimeout <= 0 {
		return errors.New("cloud idle timeout must be positive")
	}
	if p.MaximumAge <= 0 {
		return errors.New("cloud session maximum age must be positive")
	}
	if p.IdleTimeout > cloudSessionPolicyLimit {
		return errors.New("cloud idle timeout cannot exceed 30 days")
	}
	if p.MaximumAge > cloudSessionPolicyLimit {
		return errors.New("cloud session maximum age cannot exceed 30 days")
	}
	return nil
}

func (p CloudSessionPolicy) label() string {
	return fmt.Sprintf("MCP credential access (%s idle, %s max)", policyDuration(p.IdleTimeout), policyDuration(p.MaximumAge))
}

func policyDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return d.String()
}

// CloudSessionStatus is the complete public surface of an authorization session.
// Never add tokens, encrypted grants, key material or snapshot contents here.
type CloudSessionStatus struct {
	State       string `json:"state"`
	ApprovalURL string `json:"approval_url,omitempty"`
	Code        string `json:"code,omitempty"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	Message     string `json:"message"`
}

// CloudSession belongs to one stdio MCP process. Unlock material never crosses
// its public API and is never saved to the CLI account file or an SSH agent.
type CloudSession struct {
	mu           sync.Mutex
	path         string
	policy       CloudSessionPolicy
	status       CloudSessionStatus
	generation   uint64
	cancel       context.CancelFunc
	timer        *time.Timer
	state        *cloudsync.State
	master       []byte
	ownerToken   string
	ownerDevice  string
	authorizedAt time.Time
	lastUsed     time.Time
}

func NewCloudSession(path string) *CloudSession {
	s, _ := NewCloudSessionWithPolicy(path, DefaultCloudSessionPolicy())
	return s
}

func NewCloudSessionWithPolicy(path string, policy CloudSessionPolicy) (*CloudSession, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &CloudSession{path: path, policy: policy, status: CloudSessionStatus{State: "locked", Message: "Use cloud_unlock and approve its verification code in your unlocked browser. Running cloud watch does not unlock MCP."}}, nil
}

func (c *CloudSession) expireLocked() {
	if c.status.State == "ready" && (time.Since(c.lastUsed) >= c.policy.IdleTimeout || time.Since(c.authorizedAt) >= c.policy.MaximumAge || (c.state != nil && c.state.Expires <= time.Now().UnixMilli())) {
		c.lockLocked("Cloud authorization expired; use cloud_unlock for a new browser approval.")
	}
}
func (c *CloudSession) Status() CloudSessionStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	return c.status
}
func (c *CloudSession) armLocked() {
	if c.timer != nil {
		c.timer.Stop()
	}
	deadline := c.lastUsed.Add(c.policy.IdleTimeout)
	if hard := c.authorizedAt.Add(c.policy.MaximumAge); hard.Before(deadline) {
		deadline = hard
	}
	if c.state != nil {
		if tokenDeadline := time.UnixMilli(c.state.Expires); tokenDeadline.Before(deadline) {
			deadline = tokenDeadline
		}
	}
	c.status.ExpiresAt = deadline.UnixMilli()
	generation := c.generation
	c.timer = time.AfterFunc(time.Until(deadline), func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.generation == generation {
			c.expireLocked()
		}
	})
}
func revokeCloudSession(s *cloudsync.State) {
	if s == nil || s.Token == "" {
		return
	}
	// Independent copy: revocation must not retain snapshots or mutable state.
	token := &cloudsync.State{URL: s.URL, Username: s.Username, DeviceID: s.DeviceID, Token: s.Token}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = token.Request(ctx, http.MethodDelete, "/v1/devices/"+token.DeviceID, nil, nil)
		token.Token = ""
	}()
}
func (c *CloudSession) lockLocked(message string) {
	c.generation++
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	cloudsync.Wipe(c.master)
	c.master = nil
	revokeCloudSession(c.state)
	c.state = nil
	c.ownerToken = ""
	c.ownerDevice = ""
	c.status = CloudSessionStatus{State: "locked", Message: message}
}

// Close locks immediately for future connections; established operations can
// finish. Best-effort cloud revocation is asynchronous and bounded.
func (c *CloudSession) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lockLocked("Cloud session locked. Use cloud_unlock for a new browser approval.")
}

func (c *CloudSession) Begin(ctx context.Context) (CloudSessionStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	if c.status.State == "pending" || c.status.State == "ready" {
		return c.status, nil
	}
	local, err := cloudsync.LoadState(cloudsync.StatePath(c.path))
	if err != nil || local.Token == "" {
		return c.status, errors.New("cloud account is not configured or logged out; complete sshm cloud login or browser link on this device first, then use cloud_unlock")
	}
	if cloudsync.ValidateURL(local.URL) != nil {
		return c.status, errors.New("configured cloud endpoint is invalid; repair local account configuration")
	}
	s := &cloudsync.State{URL: local.URL, Username: local.Username}
	request, err := cloudsync.NewLinkRequest("", c.policy.label(), local.Base.RootPublic, false)
	if err != nil {
		return c.status, errors.New("local vault identity is invalid; verify the account in your browser before linking again")
	}
	startCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	err = s.BeginLink(startCtx, request)
	stop()
	if err != nil {
		return c.status, errors.New("could not request browser approval; check cloud connectivity and try cloud_unlock again")
	}
	remaining := time.Until(time.UnixMilli(request.Expires))
	if remaining <= 0 || remaining > 10*time.Minute+time.Second {
		return c.status, errors.New("cloud approval expiry is invalid; try again")
	}
	c.generation++
	generation := c.generation
	approvalCtx, cancel := context.WithTimeout(context.Background(), remaining)
	c.cancel = cancel
	c.ownerToken = local.Token
	c.ownerDevice = local.DeviceID
	c.status = CloudSessionStatus{State: "pending", ApprovalURL: strings.TrimRight(s.URL, "/") + "/devices", Code: cloudsync.LinkCode(request.PublicKey), ExpiresAt: request.Expires, Message: fmt.Sprintf("Approve this MCP credential-access request in your unlocked browser after comparing the code. Session policy: %s idle, %s maximum. Then call cloud_unlock_status; no password or phrase belongs in chat.", policyDuration(c.policy.IdleTimeout), policyDuration(c.policy.MaximumAge))}
	go c.waitApproval(approvalCtx, generation, s, request, local)
	return c.status, nil
}

func (c *CloudSession) waitApproval(ctx context.Context, generation uint64, s *cloudsync.State, r *cloudsync.LinkRequest, original *cloudsync.State) {
	v, err := s.WaitLink(ctx, r)
	if v != nil {
		defer v.Close()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.generation {
		revokeCloudSession(s)
		return
	}
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if err != nil {
		c.lockLocked("Browser approval failed, expired or was rejected; use cloud_unlock to request a new approval.")
		revokeCloudSession(s)
		return
	}
	local, loadErr := cloudsync.LoadState(cloudsync.StatePath(c.path))
	if loadErr != nil || local.Token != c.ownerToken || local.DeviceID != c.ownerDevice || cloudsync.InventoryIdentity(local) != cloudsync.InventoryIdentity(original) || cloudsync.InventoryIdentity(s) != cloudsync.InventoryIdentity(original) || s.Base.Revision < local.Base.Revision || s.Token == "" || s.Expires <= time.Now().UnixMilli() {
		c.lockLocked("Local account or vault changed during approval; check the account and request a new approval.")
		revokeCloudSession(s)
		return
	}
	c.state = s
	c.master = append([]byte(nil), v.Master...)
	c.authorizedAt = time.Now()
	c.lastUsed = c.authorizedAt
	c.status = CloudSessionStatus{State: "ready", Message: "Browser approval is active for this MCP process. Retry check_ssh, then the intended operation. Use cloud_lock when finished; keys are not exported."}
	c.armLocked()
}

// Resolve authenticates fresh cloud data for each new connection. A failed
// check never falls back to stale data, local keys, local agents or edited routes.
func (c *CloudSession) Resolve(ctx context.Context, target *config.Server, opts sshpkg.BuildOpts) (*config.Server, sshpkg.BuildOpts, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	fail := func(message string) (*config.Server, sshpkg.BuildOpts, func(), error) {
		return nil, sshpkg.BuildOpts{}, nil, errors.New(message)
	}
	if c.status.State != "ready" || c.state == nil {
		return fail("cloud credential is locked in this MCP process; use cloud_unlock, approve in the browser, then poll cloud_unlock_status (cloud watch cannot unlock MCP)")
	}
	local, err := cloudsync.LoadState(cloudsync.StatePath(c.path))
	if err != nil || local.Token != c.ownerToken || local.DeviceID != c.ownerDevice || cloudsync.InventoryIdentity(local) != cloudsync.InventoryIdentity(c.state) {
		c.lockLocked("Local account changed or logged out; use cloud_unlock after checking the account.")
		return fail(c.status.Message)
	}
	if target == nil || target.CloudEntry == "" || target.CloudVault != cloudsync.InventoryIdentity(c.state) {
		return fail("cloud connection does not belong to the approved account and vault")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var snapshot cloudsync.Snapshot
	if err = c.state.Request(requestCtx, http.MethodGet, "/v1/vault", nil, &snapshot); err != nil {
		var api *cloudsync.APIError
		if errors.As(err, &api) && (api.Status == 401 || api.Status == 403) {
			c.lockLocked("Cloud authorization was revoked or expired; use cloud_unlock for a new browser approval.")
			return fail(c.status.Message)
		}
		return fail("cannot verify cloud authorization; check the network and retry; offline credential access is disabled")
	}
	if snapshot.RootPublic != c.state.Base.RootPublic || snapshot.Revision < c.state.Base.Revision || snapshot.Revision < local.Base.Revision {
		c.lockLocked("Cloud vault identity changed or history rolled back; verify the vault before approving again.")
		return fail(c.status.Message)
	}
	v, err := cloudsync.UnlockMaster(c.state.Username, snapshot, c.master)
	if err != nil {
		c.lockLocked("Cloud vault authentication failed; verify the vault before approving again.")
		return fail(c.status.Message)
	}
	c.state.Base = snapshot
	c.lastUsed = time.Now()
	c.armLocked()
	entry, ok := v.Data.Entries[target.CloudEntry]
	_, conflict := v.Data.Conflicts[target.CloudEntry]
	if !ok || v.Data.Deleted[target.CloudEntry] || conflict {
		v.Close()
		return fail("cloud connection is missing, deleted or conflicted; resolve it in the vault before connecting")
	}
	if !sameMCPCloudRoute(target, &entry.Server) {
		v.Close()
		return fail("local connection route differs from the authenticated vault; sync and review the connection before retrying")
	}
	server, resolved, err := resolveCloudEntry(v.Data, entry, opts, false)
	if err != nil {
		v.Close()
		return nil, sshpkg.BuildOpts{}, nil, err
	}
	resolved.ResolveJump = func(alias string) (*config.Server, sshpkg.BuildOpts, error) {
		jump, e := v.Data.Find(strings.TrimSpace(alias))
		if e != nil {
			return nil, sshpkg.BuildOpts{}, errors.New("cloud jump host is missing or ambiguous; resolve it in the vault")
		}
		return resolveCloudEntry(v.Data, jump, opts, true)
	}
	return server, resolved, v.Close, nil
}

func sameMCPCloudRoute(a, b *config.Server) bool {
	if a.Host != b.Host || a.Port != b.Port || a.User != b.User || a.ProxyJump != b.ProxyJump || a.ProxyCommand != b.ProxyCommand || a.Proxy != b.Proxy || len(a.Forwards) != len(b.Forwards) {
		return false
	}
	for i := range a.Forwards {
		if a.Forwards[i] != b.Forwards[i] {
			return false
		}
	}
	return true
}

func resolveCloudEntry(data cloudsync.Data, entry cloudsync.Entry, opts sshpkg.BuildOpts, jump bool) (*config.Server, sshpkg.BuildOpts, error) {
	fail := func(message string) (*config.Server, sshpkg.BuildOpts, error) {
		return nil, sshpkg.BuildOpts{}, errors.New(message)
	}
	if data.Deleted[entry.ID] {
		return fail("cloud entry was deleted")
	}
	if _, ok := data.Conflicts[entry.ID]; ok {
		return fail("cloud entry has unresolved conflicts")
	}
	server := entry.Server
	if cloudsync.DeviceServerID(server) != "" {
		return fail("encrypted device terminals do not support MCP SSH commands yet; select the device's SSH server entry")
	}
	if server.ProxyCommand != "" || server.Proxy != "" || len(server.Forwards) > 0 || (jump && server.ProxyJump != "") {
		return fail("cloud route requires local review; MCP refuses ProxyCommand, SOCKS/forward rules and nested jump hosts")
	}
	opts.Signers = nil
	opts.Password = ""
	opts.ResolveCloud = nil
	opts.ResolveJump = nil
	opts.Insecure = false
	opts.StrictRoute = true
	for _, id := range entry.CredentialIDs {
		credential, ok := data.Credentials[id]
		if !ok {
			return fail("cloud connection credential is missing")
		}
		switch credential.Kind {
		case "password":
			if opts.Password != "" && opts.Password != credential.Password {
				return fail("multiple saved passwords; resolve the credential choice in the vault before connecting")
			}
			opts.Password = credential.Password
		case "key":
			signer, err := gssh.ParsePrivateKey(credential.Key)
			if err != nil && len(credential.Passphrase) > 0 {
				signer, err = gssh.ParsePrivateKeyWithPassphrase(credential.Key, credential.Passphrase)
			}
			if err != nil {
				var missing *gssh.PassphraseMissingError
				if errors.As(err, &missing) && missing.PublicKey != nil {
					var closer io.Closer
					signer, closer, err = sshpkg.AgentSignerForPublicKey(missing.PublicKey)
					if err == nil {
						opts.SignerClosers = append(opts.SignerClosers, closer)
					}
				}
			}
			if err == nil {
				opts.Signers = append(opts.Signers, signer)
			}
		}
	}
	switch server.Auth {
	case config.AuthPassword:
		if opts.Password == "" {
			return fail("server password is not saved in the vault; save it outside chat before connecting")
		}
	case config.AuthKey, config.AuthAgent:
		if len(opts.Signers) == 0 {
			return fail("no usable SSH key matched this connection: the vault copy needs its private-key passphrase and the local agent has no matching identity; load the exact key with macOS Keychain/ssh-add or replace the connection key")
		}
		server.Auth = config.AuthKey
	default:
		return fail("cloud authentication method is unsupported")
	}
	server.CloudEntry = ""
	server.CloudVault = ""
	server.KeyPath = ""
	return &server, opts, nil
}
