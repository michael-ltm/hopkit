//go:build windows

package devicekey

import (
	"context"
	"golang.org/x/sys/windows"
	"unsafe"
)

func dataBlob(b []byte) *windows.DataBlob {
	d := &windows.DataBlob{Size: uint32(len(b))}
	if len(b) > 0 {
		d.Data = &b[0]
	}
	return d
}
func copyBlob(b windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	defer clear(unsafe.Slice(b.Data, int(b.Size)))
	return append([]byte(nil), unsafe.Slice(b.Data, int(b.Size))...)
}
func (System) Seal(ctx context.Context, id string, value []byte) (string, []byte, error) {
	if e := ctx.Err(); e != nil {
		return "", nil, e
	}
	var out windows.DataBlob
	if e := windows.CryptProtectData(dataBlob(value), nil, dataBlob([]byte(id)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return "", nil, ErrUnavailable
	}
	return "dpapi-user", copyBlob(out), nil
}
func (System) Open(ctx context.Context, id, backend string, blob []byte) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if backend != "dpapi-user" {
		return nil, ErrUnavailable
	}
	var out windows.DataBlob
	if e := windows.CryptUnprotectData(dataBlob(blob), nil, dataBlob([]byte(id)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); e != nil {
		return nil, ErrUnavailable
	}
	return copyBlob(out), nil
}
