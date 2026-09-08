package cloudagent

import (
	"context"
	"errors"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"time"
)

// Resolve the ID from a freshly verified vault, never accept a browser-supplied
// command, hostname, key path or proxy command. No credential leaves this process.
func openTarget(ctx context.Context, state *cloudsync.State, master []byte, path string, p cloudsync.ShellPayload) (terminal, error) {
	if len(p.Target) != 64 || len(p.Credential) > 100 || !validSize(p.Cols, p.Rows) {
		return nil, errors.New("invalid_target")
	}
	var snap cloudsync.Snapshot
	if state.Request(ctx, "GET", "/v1/vault", nil, &snap) != nil {
		return nil, errors.New("vault_unavailable")
	}
	v, err := cloudsync.UnlockMaster(state.Username, snap, master)
	if err != nil {
		return nil, errors.New("vault_unavailable")
	}
	defer v.Close()
	entry, ok := v.Data.Entries[p.Target]
	if !ok || v.Data.Deleted[p.Target] {
		return nil, errors.New("target_removed")
	}
	if _, ok = v.Data.Conflicts[p.Target]; ok {
		return nil, errors.New("target_conflict")
	}
	cfg, _ := config.Load(path)
	target, opts, err := targetOptions(v.Data, entry, cfg, path, p.Credential)
	if err != nil {
		return nil, err
	}
	// Dial has bounded transport/handshake deadlines; do not block relay reads.
	client, err := sshpkg.Dial(&target, opts)
	if err != nil {
		return nil, errors.New("ssh_" + sshpkg.FailureCategory(err))
	}
	if ctx.Err() != nil {
		client.Close()
		return nil, ctx.Err()
	}
	tty, err := client.OpenTerminal(ctx, p.Cols, p.Rows)
	if err != nil {
		client.Close()
		return nil, errors.New("pty_unavailable")
	}
	if opts.Alias != "" {
		_ = config.RecordSSHUse(path, opts.Alias, &target, time.Now())
	}
	return tty, nil
}
func targetOptions(data cloudsync.Data, entry cloudsync.Entry, cfg *config.Config, path, credential string) (config.Server, sshpkg.BuildOpts, error) {
	target := entry.Server
	opts := sshpkg.BuildOpts{ConfigPath: path, Timeout: 8 * time.Second, ProbeOnly: true}
	// Source aliases are hints only: the current local identity must still match
	// exactly before using its private path or locally configured route.
	if cfg != nil {
		for alias, s := range cfg.Servers {
			if s != nil && cloudsync.EntryID(*s) == entry.ID {
				target.KeyPath = s.KeyPath
				opts.Alias = alias
				break
			}
		}
	}
	if (target.ProxyCommand != "" || target.ProxyJump != "" || target.Proxy != "" || len(target.Forwards) > 0) && opts.Alias == "" {
		return target, opts, errors.New("source_device_required")
	}
	// An interactive terminal does not implicitly open configured forwarding ports.
	target.Forwards = nil
	matched := credential == ""
	var signers []gssh.Signer
	for _, id := range entry.CredentialIDs {
		if credential != "" && credential != id {
			continue
		}
		matched = true
		c := data.Credentials[id]
		if target.Auth == config.AuthPassword && c.Kind == "password" {
			if opts.Password != "" && opts.Password != c.Password {
				return target, opts, errors.New("choose_credential")
			}
			opts.Password = c.Password
		}
		if target.Auth == config.AuthKey && c.Kind == "key" {
			s, e := gssh.ParsePrivateKey(c.Key)
			if e != nil && len(c.Passphrase) > 0 {
				s, e = gssh.ParsePrivateKeyWithPassphrase(c.Key, c.Passphrase)
			}
			if e == nil {
				signers = append(signers, s)
			}
		}
	}
	if !matched {
		return target, opts, errors.New("invalid_credential")
	}
	opts.Signers = signers
	if target.Auth == config.AuthKey && len(signers) == 0 && (target.KeyPath == "" || credential != "") {
		return target, opts, errors.New("key_locked")
	}
	if target.Auth == config.AuthPassword && opts.Password == "" {
		return target, opts, errors.New("password_unavailable")
	}
	// Local ProxyJump resolution uses the chosen device's reviewed configuration.
	// Alias is used only after a shell actually starts, not after authentication.
	return target, opts, nil
}
