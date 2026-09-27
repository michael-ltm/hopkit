// Package localservice provides a private compatibility agent for persisted
// local credentials. SSH itself does not depend on this process.
package localservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrRunning = errors.New("local service is already running")
var errDenied = errors.New("local agent operation denied")

func instance(configPath string) string {
	sum := sha256.Sum256([]byte(localstore.New(configPath).ConfigPath))
	return hex.EncodeToString(sum[:16])
}

type ServiceStatus struct {
	Running    bool       `json:"running"`
	Configured bool       `json:"configured"`
	Locked     bool       `json:"locked"`
	Socket     string     `json:"socket"`
	Startup    bool       `json:"startup"`
	Sync       SyncStatus `json:"sync"`
}

func Status(configPath string) ServiceStatus {
	s := localstore.New(configPath)
	status := ServiceStatus{Running: active(s.ConfigPath), Configured: s.Enabled(), Locked: s.CheckLocked() != nil, Socket: SocketPath(s.ConfigPath), Startup: startupInstalled(s.ConfigPath), Sync: readSyncStatus(s.ConfigPath)}
	if status.Locked {
		status.Sync.State = "locked"
	}
	return status
}
func active(configPath string) bool {
	c, e := dialEndpoint(context.Background(), SocketPath(configPath))
	if e != nil {
		return false
	}
	defer c.Close()
	return sameUser(c)
}

// Ensure starts a detached service only for an initialized store. It never
// opens the device protector or changes the persisted explicit lock.
func Ensure(ctx context.Context, configPath string) error {
	s := localstore.New(configPath)
	if !s.Enabled() || active(s.ConfigPath) {
		return nil
	}
	if e := prepareRuntime(s.ConfigPath); e != nil {
		return e
	}
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	// Service errors are intentionally discarded: provider diagnostics may carry
	// sensitive payloads, and stdout belongs to the MCP protocol in MCP callers.
	devnull, e := os.OpenFile(os.DevNull, os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer devnull.Close()
	cmd := exec.Command(binary, "--config", s.ConfigPath, "service", "run")
	cmd.Stdin = devnull
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	detach(cmd)
	if e = cmd.Start(); e != nil {
		return errors.New("could not start local service")
	}
	go func() { _ = cmd.Wait() }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if active(s.ConfigPath) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("local service did not become ready")
		case <-ticker.C:
		}
	}
}

func Run(ctx context.Context, store *localstore.Store, background func(context.Context)) error {
	if !store.Enabled() {
		return localstore.ErrNotFound
	}
	if e := prepareRuntime(store.ConfigPath); e != nil {
		return e
	}
	release, e := processLock(store.ConfigPath)
	if e != nil {
		return e
	}
	defer release()
	ln, e := listenEndpoint(store.ConfigPath)
	if e != nil {
		return e
	}
	defer ln.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	clients := map[net.Conn]struct{}{}
	var wg sync.WaitGroup
	closed := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
		case <-closed:
			return
		}
		_ = ln.Close()
		mu.Lock()
		for c := range clients {
			_ = c.Close()
		}
		mu.Unlock()
	}()
	defer close(closed)
	if background != nil {
		backgroundDone := make(chan struct{})
		go func() { defer close(backgroundDone); background(runCtx) }()
		defer func() {
			cancel()
			timer := time.NewTimer(500 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-backgroundDone:
			case <-timer.C:
			}
		}()
	}
	handler := &persistentAgent{ctx: runCtx, store: store}
	for {
		conn, e := ln.Accept()
		if e != nil {
			cancel()
			mu.Lock()
			for c := range clients {
				_ = c.Close()
			}
			mu.Unlock()
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("local service listener failed")
		}
		if !sameUser(conn) {
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if runCtx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		clients[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			defer func() { mu.Lock(); delete(clients, conn); mu.Unlock() }()
			_ = agent.ServeAgent(handler, conn)
		}()
	}
}

// A service manager may start after an MCP-launched instance. Wait for that
// instance to stop, then take over under the same process lock. Detached MCP
// starters use Run directly so concurrent starts never accumulate waiters.
func RunSupervised(ctx context.Context, store *localstore.Store, background func(context.Context)) error {
	for {
		err := Run(ctx, store, background)
		if !errors.Is(err, ErrRunning) {
			return err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

type persistentAgent struct {
	ctx   context.Context
	store *localstore.Store
}

func (a *persistentAgent) withSigners(fn func(ssh.Signer) error) error {
	if a.store.CheckLocked() != nil {
		return errDenied
	}
	cfg, e := config.Load(a.store.ConfigPath)
	if e != nil {
		return errDenied
	}
	for _, target := range cfg.Servers {
		if target == nil {
			continue
		}
		cs, e := a.store.Resolve(a.ctx, target)
		if errors.Is(e, localstore.ErrNotFound) || errors.Is(e, localstore.ErrInactive) {
			continue
		}
		if e != nil {
			return errDenied
		}
		for _, c := range cs {
			if len(c.Key) == 0 {
				continue
			}
			signer, e := c.Signer()
			if e != nil {
				localstore.CloseCredentials(cs)
				return errDenied
			}
			if e = fn(signer); e != nil {
				localstore.CloseCredentials(cs)
				return e
			}
		}
		localstore.CloseCredentials(cs)
	}
	return nil
}
func (a *persistentAgent) List() ([]*agent.Key, error) {
	keys := []*agent.Key{}
	seen := map[string]bool{}
	e := a.withSigners(func(s ssh.Signer) error {
		blob := s.PublicKey().Marshal()
		if !seen[string(blob)] {
			seen[string(blob)] = true
			keys = append(keys, &agent.Key{Format: s.PublicKey().Type(), Blob: blob, Comment: "sshm local credential"})
		}
		return nil
	})
	return keys, e
}
func (a *persistentAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}
func (a *persistentAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	var signature *ssh.Signature
	e := a.withSigners(func(s ssh.Signer) error {
		if signature != nil || !bytes.Equal(key.Marshal(), s.PublicKey().Marshal()) {
			return nil
		}
		if a.store.CheckLocked() != nil {
			return errDenied
		}
		var e error
		switch flags {
		case 0:
			signature, e = s.Sign(rand.Reader, data)
		case agent.SignatureFlagRsaSha256, agent.SignatureFlagRsaSha512:
			alg, ok := s.(ssh.AlgorithmSigner)
			if !ok || s.PublicKey().Type() != ssh.KeyAlgoRSA {
				return errDenied
			}
			name := ssh.KeyAlgoRSASHA256
			if flags == agent.SignatureFlagRsaSha512 {
				name = ssh.KeyAlgoRSASHA512
			}
			signature, e = alg.SignWithAlgorithm(rand.Reader, data, name)
		default:
			return errDenied
		}
		if e != nil {
			return errDenied
		}
		return nil
	})
	if e != nil || signature == nil {
		return nil, errDenied
	}
	return signature, nil
}
func (*persistentAgent) Add(agent.AddedKey) error       { return errDenied }
func (*persistentAgent) Remove(ssh.PublicKey) error     { return errDenied }
func (*persistentAgent) RemoveAll() error               { return errDenied }
func (*persistentAgent) Lock([]byte) error              { return errDenied }
func (*persistentAgent) Unlock([]byte) error            { return errDenied }
func (*persistentAgent) Signers() ([]ssh.Signer, error) { return nil, errDenied }
func (*persistentAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func privateWrite(path string, data []byte) error {
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("unsafe service file")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".sshm-service-*")
	if e != nil {
		return e
	}
	defer f.Close()
	defer os.Remove(f.Name())
	if e = protectFile(f.Name()); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
