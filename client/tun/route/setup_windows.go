//go:build windows

package route

import (
	"fmt"
	"github.com/fmnx/cftun/log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func getDefaultGateway(is6 bool) (idx, gateway string) {
	var substr string
	var cmd *exec.Cmd
	if is6 {
		substr = "::/0"
		cmd = exec.Command("netsh", "interface", "ipv6", "show", "route")
	} else {
		substr = "0.0.0.0/0"
		cmd = exec.Command("netsh", "interface", "ipv4", "show", "route")
	}
	out, err := cmd.Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	metric := int64(65536)
	for _, line := range lines {
		if strings.Contains(line, substr) {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				newMetric, pe := strconv.ParseInt(parts[2], 10, 64)
				if pe != nil || newMetric >= metric {
					continue
				}
				metric = newMetric
				idx, gateway = parts[4], parts[5]
			}
		}
	}
	return
}

func getIPv4DefaultGateway() (gateway, iface string) {
	return getDefaultGateway(false)
}

func getIPv6DefaultGateway() (gateway, iface string) {
	return getDefaultGateway(true)
}

func configureAddressImpl(tunName, ipv4, ipv6 string) {
	log.Infoln("[Route] Configuring IP address for WinTun adapter %s...", tunName)
	var err error

	// 核心优化：自适应循环重试 5 次，每次休眠 300ms，等待 Windows 物理网卡就绪后再配置 IP
	for i := 0; i < 5; i++ {
		err = exec.Command("netsh", "interface", "ipv4", "set", "address", tunName, "static", ipv4).Run()
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		log.Errorln("[Route] Failed to add IPv4 address to %s: %v", tunName, err)
	} else {
		log.Infoln("[Route] IPv4 address %s configured on %s successfully.", ipv4, tunName)
	}

	for i := 0; i < 5; i++ {
		err = exec.Command("netsh", "interface", "ipv6", "add", "address", tunName, ipv6).Run()
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		log.Warnln("[Route] Failed to add IPv6 address to %s: %v (Usually safe to ignore)", tunName, err)
	}

	// 配置 DNS，同样引入就绪重试
	for i := 0; i < 5; i++ {
		err = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", fmt.Sprintf("name=%s", tunName),
			"static", "address=8.8.8.8", "register=none", "validate=no").Run()
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		log.Errorln("[Route] Failed to set DNS for %s: %v", tunName, err)
	}
}

func configureRouteImpl(tunName, ipv4, ipv6 string, routes, exRoutes []string) {
	log.Infoln("[Route] Applying routing tables to Windows...")
	
	for _, route := range routes {
		var err error
		for i := 0; i < 5; i++ {
			if strings.Contains(route, ":") {
				if !strings.Contains(route, "/") {
					route += "/128"
				}
				err = exec.Command("netsh", "interface", "ipv6", "add", "route", route, tunName, ipv6, "metric=1").Run()
			} else {
				if !strings.Contains(route, "/") {
					route += "/32"
				}
				err = exec.Command("netsh", "interface", "ipv4", "add", "route", route, tunName, ipv4, "metric=1").Run()
			}
			if err == nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if err != nil {
			log.Errorln("[Route] Failed to add route %s on %s: %v", route, tunName, err)
		} else {
			log.Infoln("[Route] Route %s applied to %s successfully.", route, tunName)
		}
	}

	if len(exRoutes) > 0 {
		idx4, gateway4 := getIPv4DefaultGateway()
		idx6, gateway6 := getIPv6DefaultGateway()

		for _, route := range exRoutes {
			var err error
			for i := 0; i < 5; i++ {
				if strings.Contains(route, ":") {
					if !strings.Contains(route, "/") {
						route += "/128"
					}
					err = exec.Command("netsh", "interface", "ipv6", "add", "route", route, idx6, gateway6, "metric=1").Run()
				} else {
					if !strings.Contains(route, "/") {
						route += "/32"
					}
					err = exec.Command("netsh", "interface", "ipv4", "add", "route", route, idx4, gateway4, "metric=1").Run()
				}
				if err == nil {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if err != nil {
				log.Errorln("[Route] Failed to add exRoute %s: %v", route, err)
			}
		}
	}
}
