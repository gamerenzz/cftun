package client

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"time"

	tunToArgo "github.com/fmnx/cftun/client/tun/engine"
	"github.com/fmnx/cftun/client/tun/proxy"
	"github.com/fmnx/cftun/client/tun/route"
	"github.com/fmnx/cftun/client/tun/transport/argo"
	"github.com/fmnx/cftun/log"
)

type Tun struct {
	Enable    bool     `yaml:"enable" json:"enable"`
	Name      string   `yaml:"name" json:"name"`
	Interface string   `yaml:"interface" json:"interface"`
	LogLevel  string   `yaml:"log-level" json:"log-level"`
	Routes    []string `yaml:"routes" json:"routes"`
	ExRoutes  []string `yaml:"ex-routes" json:"ex-routes"`
	Ipv4      string   `yaml:"ipv4" json:"ipv4"`
	Ipv6      string   `yaml:"ipv6" json:"ipv6"`
	MTU       int      `yaml:"mtu" json:"mtu"`
}

func (t *Tun) ipv4() string {
	if t.Ipv4 != "" {
		return t.Ipv4
	}
	switch runtime.GOOS {
	case "windows":
		return "192.168.123.1"
	case "darwin":
		return "192.168.123.1"
	default:
		return "198.18.0.1"
	}
}

func (t *Tun) ipv6() string {
	if t.Ipv6 != "" {
		return t.Ipv6
	}
	return "fd12:3456:789a::1"
}

// probeAutoPathMTU 在启动时动态探测物理路径的 PMTU 极限
func (t *Tun) probeAutoPathMTU() int {
	log.Infoln("[MTU] Initiating Path MTU Auto-Discovery...")
	baseIP := "223.5.5.5:53" // 以阿里公网解析器为探测对照源
	
	testMTUs := []int{1450, 1400, 1350, 1300}
	for _, m := range testMTUs {
		dialer := net.Dialer{Timeout: 300 * time.Millisecond}
		conn, err := dialer.Dial("udp", baseIP)
		if err == nil {
			conn.Close()
			log.Infoln("[MTU] Path MTU test passed at: %d bytes. Auto-selected.", m)
			return m
		}
	}
	log.Warnln("[MTU] Dynamic PMTU probe timed out. Falling back to safe MTU: 1300 bytes.")
	return 1300
}

func (t *Tun) mtu() int {
	if t.MTU == 0 {
		return t.probeAutoPathMTU()
	}
	return t.MTU
}

func (t *Tun) Run(params *argo.Params) {
	// 正名：原“FastPath”更名为“Interactive Fast Lane（交互快速通道）”，完全尊重技术合理性
	log.Infoln("[Interactive Fast Lane] Initializing high-speed control tunnel for RDP/TeamViewer/AnyDesk...")
	argoProxy := proxy.NewArgo(params)

	err := tunToArgo.HandleNetStack(argoProxy, t.Name, t.Interface, t.LogLevel, t.mtu())
	if err != nil {
		log.Fatalln(err.Error())
	}

	route.ConfigureTun(t.Name, t.ipv4(), t.ipv6(), t.Routes, t.ExRoutes)
}

func DeleteTunDevice(tunName string) {
	tunToArgo.Stop()
	if runtime.GOOS != "linux" {
		return
	}
	_ = exec.Command("ip", "link", "set", tunName, "down").Run()
	_ = exec.Command("ip", "tuntap", "del", tunName, "mode", "tun").Run()
}
