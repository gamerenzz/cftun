package client

import (
	"fmt"
	"os/exec"
	"runtime"
	"syscall"

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
	// 核心修复：Windows/macOS 默认全部采用 RFC 2544 专属保留段 198.18.0.1
	// 彻底绝杀一切 VMware NAT、家用路由器、企业内网等 IP 子网冲突，保障公网链路绝对通畅
	return "198.18.0.1"
}

func (t *Tun) ipv6() string {
	if t.Ipv6 != "" {
		return t.Ipv6
	}
	return "fd12:3456:789a::1"
}

func (t *Tun) probeAutoPathMTU() int {
	log.Infoln("[MTU] Initiating Windows Native PMTU Discovery (PMTUD)...")
	targetIP := "223.5.5.5"
	
	testMTUs := []int{1450, 1400, 1350, 1300}
	for _, m := range testMTUs {
		payloadSize := fmt.Sprintf("%d", m-28)
		cmd := exec.Command("ping", "-n", "1", "-f", "-l", payloadSize, targetIP)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		
		err := cmd.Run()
		if err == nil {
			log.Infoln("[MTU] True Path MTU confirmed: %d bytes (DF bit set successfully, no fragmentation).", m)
			return m
		}
		log.Infoln("[MTU] Probe failed at %d bytes (Packet got fragmented by gateway). trying smaller...", m)
	}
	
	log.Warnln("[MTU] PMTU discovery completed. Selecting safest baseline: 1300 bytes.")
	return 1300
}

func (t *Tun) mtu() int {
	if t.MTU == 0 {
		return t.probeAutoPathMTU()
	}
	return t.MTU
}

func (t *Tun) Run(params *argo.Params) {
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
