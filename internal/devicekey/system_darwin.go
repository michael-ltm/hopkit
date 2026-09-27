//go:build darwin

package devicekey

import (
	"context"
	"crypto/rand"
)

func (System) Seal(ctx context.Context, id string, value []byte) (string, []byte, error) {
	if !validInstance(id) {
		return "", nil, ErrUnavailable
	}
	ref, e := newReference()
	if e != nil {
		return "", nil, e
	}
	key, e := keychainKey(ctx, ref, true)
	if e != nil {
		return "", nil, e
	}
	defer clear(key)
	b, e := wrap(key, value, id)
	return "keychain:" + ref, b, e
}
func (System) Open(ctx context.Context, id, backend string, blob []byte) ([]byte, error) {
	ref, e := reference(backend, "keychain")
	if e != nil {
		return nil, e
	}
	key, e := keychainKey(ctx, ref, false)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	return unwrap(key, blob, id)
}
func keychainKey(ctx context.Context, id string, create bool) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !create {
		return readKeychainKey(id)
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, e
	}
	defer clear(key)
	if e := addKeychainKey(id, key); e != nil {
		return nil, e
	}
	return readKeychainKey(id)
}
