//go:build !linux && !darwin && !windows

package devicekey

import "context"

func (System) Seal(context.Context, string, []byte) (string, []byte, error) {
	return "", nil, ErrUnavailable
}
func (System) Open(context.Context, string, string, []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
