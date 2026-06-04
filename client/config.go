package client

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fmnx/cftun/client/tun/transport/argo"
	"github.com/fmnx/cftun/log"
)

type Tunnel struct {
	Listen   string `yaml:"listen" json:"listen"`
	Remote   string `yaml:"remote" json:"remote"`
	Url      string `yaml:"url" json:"url"`
	Protocol string `yaml:"protocol" json:"protocol"`
	Timeout  int    `yaml:"timeout" json:"timeout"`
}

type Config struct {
	CdnIp     string    `yaml:"cdn-ip" json:"cdn-ip"`
	CdnPort   int       `yaml:"cdn-port" json:"cdn-port"`
	PoolSize  int32     `yaml:"pool-size" json:"pool-size"`
	GlobalUrl string    `yaml:"global-url" json:"global-url"`
	Scheme    string    `yaml:"scheme" json:"scheme"`
	Tunnels   []*Tunnel `yaml:"tunnels" json:"tunnels"`
	Tun       *Tun      `yaml:"tun" json:"tun"`
}

var defaultCfIps = []string{
	"104.16.123.96", "104.17.143.163", "104.16.249.249",
	"162.159.192.1", "108.162.192.1", "172.64.161.11",
}

type ProbeResult struct {
	IP     string
	RTT    time.Duration
	Jitter time.Duration
	Loss   float64
}

func (p *ProbeResult) Score() float64 {
	// RTT占40%, 丢包占40%, 抖动占20% (远程控制场景最核心指标)
	return float64(p.RTT.Milliseconds())*0.4 + p.Loss*1000.0*0.4 + float64(p.Jitter.Milliseconds())*0.2
}

// SelectBestIP 执行高精度的并发链路评分探测
func SelectBestIP() string {
	log.Infoln("[Optimizer] Rerouting initiated. Probing Cloudflare nodes...")
	var wg sync.WaitGroup
	var mu sync.Mutex
	bestIP := defaultCfIps[0]
	minScore := 999999.0

	for _, ip := range defaultCfIps {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			var rtts []time.Duration
			successCount := 0
			probeTimes := 5 // 每个节点测试5次获取抖动与丢包

			for i := 0; i < probeTimes; i++ {
				start := time.Now()
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, "443"), 300*time.Millisecond)
				if err == nil {
					conn.Close()
					rtts = append(rtts, time.Since(start))
					successCount++
				}
				time.Sleep(10 * time.Millisecond)
			}

			if successCount == 0 {
				return
			}

			// 计算 RTT, Jitter, Loss
			var sum int64
			for _, r := range rtts {
				sum += r.Milliseconds()
			}
			avgRtt := time.Duration(sum/int64(successCount)) * time.Millisecond

			var jitterSum int64
			for i := 1; i < len(rtts); i++ {
				diff := rtts[i].Milliseconds() - rtts[i-1].Milliseconds()
				if diff < 0 {
					diff = -diff
				}
				jitterSum += diff
			}
			avgJitter := time.Millisecond
			if successCount > 1 {
				avgJitter = time.Duration(jitterSum/int64(successCount-1)) * time.Millisecond
			}

			lossRate := float64(probeTimes-successCount) / float64(probeTimes)

			res := &ProbeResult{
				IP:     target,
				RTT:    avgRtt,
				Jitter: avgJitter,
				Loss:   lossRate,
			}

			score := res.Score()
			mu.Lock()
			if score < minScore {
				minScore = score
				bestIP = target
			}
			mu.Unlock()
			log.Infoln("[Optimizer] Node: %s | RTT: %v | Jitter: %v | Loss: %.1f%% | Score: %.2f",
				target, avgRtt, avgJitter, lossRate*100, score)
		}(ip)
	}
	wg.Wait()
	log.Infoln("[Optimizer] Route decided. Best Node: %s (Rank Score: %.2f)", bestIP, minScore)
	return bestIP
}

func (c *Config) Run() {
	if c.CdnIp == "" || c.CdnIp == "auto" {
		c.CdnIp = SelectBestIP()
	}

	if c.Tun != nil && c.Tun.Enable {
		params := &argo.Params{
			Scheme:   c.getScheme(),
			CdnIP:    c.CdnIp,
			Url:      c.GlobalUrl,
			Port:     c.getPort(),
			PoolSize: c.getPoolSize(),
		}
		c.Tun.Run(params)
	}

	for _, tunnel := range c.Tunnels {
		if tunnel.Url == "" {
			tunnel.Url = c.GlobalUrl
		}
		switch tunnel.Protocol {
		case "udp":
			go UdpListen(c, tunnel)
		case "tcp":
			go TcpListen(c, tunnel)
		default:
			tunnel.Protocol = "tcp"
			go TcpListen(c, tunnel)
		}
	}
}

func (c *Config) getAddress() string {
	if strings.Contains(c.CdnIp, ":") && !strings.Contains(c.CdnIp, "[") {
		return fmt.Sprintf("[%s]:%d", c.CdnIp, c.getPort())
	}
	return fmt.Sprintf("%s:%d", c.CdnIp, c.getPort())
}

func (c *Config) getPort() int {
	if c.CdnPort == 0 {
		return 443
	}
	return c.CdnPort
}

func (c *Config) getPoolSize() int32 {
	if c.PoolSize == 0 {
		return 10
	}
	return c.PoolSize
}

func (c *Config) getScheme() string {
	if c.Scheme != "" {
		return c.Scheme
	}
	switch c.getPort() {
	case 80, 8080, 8880, 2052, 2082, 2086, 2095:
		return "ws"
	default:
		return "wss"
	}
}

