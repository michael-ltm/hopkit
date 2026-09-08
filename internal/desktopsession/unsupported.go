//go:build !darwin

package desktopsession

import (
	"context"
	"io"
)

func Enable(context.Context, string) (Status, error) { return Status{}, ErrUnsupported }
func Disable(context.Context) error                  { return ErrUnsupported }
func Inspect(context.Context) Status                 { return Status{} }
func Serve(context.Context, string) error            { return ErrUnsupported }
func Execute(context.Context, string, string, io.Writer, io.Writer) (int, error) {
	return -1, ErrUnsupported
}
func RunGitHub(context.Context, []string, io.Reader, io.Writer, io.Writer) (int, error) {
	return -1, ErrUnsupported
}
