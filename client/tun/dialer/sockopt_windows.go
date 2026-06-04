package dialer

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func setSocketOptions(network, address string, c syscall.RawConn, opts *Options) (err error) {
	if opts == nil || !isTCPSocket(network) && !isUDPSocket(network) {
		return
	}

	var innerErr error
	err = c.Control(func(fd uintptr) {
		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if ip != nil && !ip.IsGlobalUnicast() {
			return
		}

		if opts.InterfaceIndex == 0 && opts.InterfaceName != "" {
			if iface, err := net.InterfaceByName(opts.InterfaceName); err == nil {
				opts.InterfaceIndex = iface.Index
			}
		}

		if opts.InterfaceIndex != 0 {
			switch network {
			case "tcp4", "udp4":
				innerErr = bindSocketToInterface4(windows.Handle(fd), uint32(opts.InterfaceIndex))
			case "tcp6", "udp6":
				innerErr = bindSocketToInterface6(windows.Handle(fd), uint32(opts.InterfaceIndex))
				if network == "udp6" && ip == nil {
					innerErr = bindSocketToInterface4(windows.Handle(fd), uint32(opts.InterfaceIndex))
				}
			}
		}
	})

	if innerErr != nil {
		err = innerErr
	}
	return
}

func bindSocketToInterface4(handle windows.Handle, index uint32) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(index))
}

func bindSocketToInterface6(handle windows.Handle, index uint32) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(index))
}
