//go:build linux

package devicekey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

func (System) Seal(ctx context.Context, id string, value []byte) (string, []byte, error) {
	// The system's host secret is outside the SSHM data/backup directory.
	if blob, e := runCommand(ctx, value, "systemd-creds", "--user", "--name="+id, "--with-key=host", "--no-ask-password", "encrypt", "-", "-"); e == nil && len(blob) > 0 {
		return "systemd-user", blob, nil
	} else if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return "", nil, commandFailure(e)
	}
	ref, e := newReference()
	if e != nil {
		return "", nil, e
	}
	key, e := secretKey(ctx, ref, true)
	if e != nil {
		return "", nil, commandFailure(e)
	}
	defer clear(key)
	blob, e := wrap(key, value, id)
	return "secret-service:" + ref, blob, e
}
func (System) Open(ctx context.Context, id, backend string, blob []byte) ([]byte, error) {
	switch backend {
	case "systemd-user":
		b, e := runCommand(ctx, blob, "systemd-creds", "--user", "--name="+id, "--no-ask-password", "decrypt", "-", "-")
		if e != nil {
			return nil, commandFailure(e)
		}
		return b, nil
	default:
		ref, e := reference(backend, "secret-service")
		if e != nil {
			return nil, e
		}
		key, e := secretKey(ctx, ref, false)
		if e != nil {
			return nil, e
		}
		defer clear(key)
		return unwrap(key, blob, id)
	}
}
func secretKey(ctx context.Context, id string, create bool) ([]byte, error) {
	read := func() ([]byte, error) {
		// search without --unlock must never trigger a keyring password dialog.
		b, e := runCommand(ctx, nil, "secret-tool", "search", "--all", "application", "sshm", "instance", id)
		if e != nil {
			return nil, e
		}
		defer clear(b)
		value := ""
		count := 0
		for _, line := range strings.Split(string(b), "\n") {
			if secret, ok := strings.CutPrefix(line, "secret = "); ok {
				count++
				if count > 1 {
					return nil, ErrUnavailable
				}
				value = strings.TrimSpace(secret)
			}
		}
		key, e := base64.StdEncoding.DecodeString(value)
		if e != nil || len(key) != 32 {
			clear(key)
			return nil, ErrUnavailable
		}
		return key, nil
	}
	if !create {
		return read()
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, e
	}
	defer clear(key)
	encoded := []byte(base64.StdEncoding.EncodeToString(key))
	defer clear(encoded)
	if _, e := runCommand(ctx, encoded, "secret-tool", "store", "--label=SSHM device protection", "application", "sshm", "instance", id); e != nil {
		return nil, e
	}
	return read()
}
