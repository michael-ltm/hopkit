// Package devicekey protects device unlock material with operating-system
// facilities. It deliberately has no plaintext or app-directory key fallback.
package devicekey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

var ErrUnavailable = errors.New("device protection unavailable; run 'sshm service setup' in a local terminal to configure this device")

type Protector interface {
	Seal(context.Context, string, []byte) (string, []byte, error)
	Open(context.Context, string, string, []byte) ([]byte, error)
}
type System struct{}

func wrap(key, value []byte, id string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, a.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, value, []byte(id)), nil
}
func unwrap(key, value []byte, id string) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(value) < a.NonceSize() {
		return nil, ErrUnavailable
	}
	return a.Open(nil, value[:a.NonceSize()], value[a.NonceSize():], []byte(id))
}

func newReference() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func reference(backend, prefix string) (string, error) {
	r, ok := strings.CutPrefix(backend, prefix+":")
	if !ok || len(r) != 32 {
		return "", ErrUnavailable
	}
	if _, e := hex.DecodeString(r); e != nil {
		return "", ErrUnavailable
	}
	return r, nil
}
func validInstance(id string) bool {
	raw, ok := strings.CutPrefix(id, "sshm-")
	if !ok || len(raw) != 64 {
		return false
	}
	_, e := hex.DecodeString(raw)
	return e == nil
}
