package cloudagent

import "io"

type terminal interface {
	io.ReadWriteCloser
	Resize(cols, rows int) error
}

func validSize(cols, rows int) bool { return cols >= 20 && cols <= 300 && rows >= 5 && rows <= 150 }
