//go:build windows
// +build windows

package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const IP_TOS = 3

// SetSocketTOS 在 Windows 底层设置连接的 IP_TOS 属性
func SetSocketTOS(conn net.Conn, tos int) {
	type rawConn interface {
		SyscallConn() (syscall.RawConn, error)
	}

	var sc syscall.RawConn
	if rc, ok := conn.(rawConn); ok {
		var err error
		sc, err = rc.SyscallConn()
		if err != nil {
			return
		}
	} else {
		return
	}

	_ = sc.Control(func(fd uintptr) {
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_TOS, tos)
	})
}

