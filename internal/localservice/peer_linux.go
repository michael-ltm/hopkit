//go:build linux

package localservice

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
)

func sameUser(conn net.Conn) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	allowed := false
	e = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = e == nil && cred.Uid == uint32(os.Getuid())
	})
	return e == nil && allowed
}
