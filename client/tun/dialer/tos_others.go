//go:build !windows
// +build !windows

package dialer

import "net"

// SetSocketTOS 在非 Windows 平台仅作编译占位，不做任何操作
func SetSocketTOS(conn net.Conn, tos int) {
	// No-op
}
