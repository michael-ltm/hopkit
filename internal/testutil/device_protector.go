// Package testutil provides fixtures for tests across internal packages.
package testutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// DeviceProtector models an OS key kept outside the encrypted application
// store. This package is imported only by _test.go files.
type DeviceProtector struct{ key [32]byte }

func NewDeviceProtector() *DeviceProtector {
	p := &DeviceProtector{}
	if _, e := rand.Read(p.key[:]); e != nil {
		panic(e)
	}
	return p
}
func (p *DeviceProtector) aead() cipher.AEAD {
	b, _ := aes.NewCipher(p.key[:])
	a, _ := cipher.NewGCM(b)
	return a
}
func (p *DeviceProtector) Seal(_ context.Context, id string, b []byte) (string, []byte, error) {
	a := p.aead()
	n := make([]byte, a.NonceSize())
	_, e := rand.Read(n)
	if e != nil {
		return "", nil, e
	}
	return "fixture", a.Seal(n, n, b, []byte(id)), nil
}
func (p *DeviceProtector) Open(_ context.Context, id, backend string, b []byte) ([]byte, error) {
	a := p.aead()
	if backend != "fixture" || len(b) < a.NonceSize() {
		return nil, errors.New("invalid test device wrapper")
	}
	return a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(id))
}
