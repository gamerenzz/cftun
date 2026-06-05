package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fmnx/cftun/client/tun/dialer"
	"github.com/fmnx/cftun/client/tun/transport/argo"
	"github.com/fmnx/cftun/log"
	"github.com/gorilla/websocket"
)

type Websocket struct {
	config       *Config
	tunnel       *Tunnel
	wsDialer     *websocket.Dialer
	url          string
	headers      http.Header
	latencyValue atomic.Int64
	lossCounter  atomic.Uint32
}

func NewWebsocket(config *Config, tunnel *Tunnel) *Websocket {
	host := strings.Split(tunnel.Url, "/")[0]
	
	// 核心安全升级：显式注入 TLS SNI 服务器名称，防止 IP 直连时被 Cloudflare 拒绝
	wsDialer := &websocket.Dialer{
		TLSClientConfig:   &tls.Config{ServerName: host},
		Proxy:             http.ProxyFromEnvironment,
	}

	dial := net.Dial
	if !strings.Contains(tunnel.Listen, "0.0.0.0") && !strings.Contains(tunnel.Listen, "127.0.0.1") {
		localIP, _, _ := net.SplitHostPort(tunnel.Listen)
		localAddr := &net.TCPAddr{
			IP:   net.ParseIP(localIP),
			Port: 0,
		}
		dial = (&net.Dialer{
			LocalAddr: localAddr,
			Timeout:   5 * time.Second,
		}).Dial
	}

	wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
		if config.CdnIp != "" {
			return dial(network, config.getAddress())
		}
		return dial(network, addr)
	}

	// 核心安全升级：伪装成标准的 Windows 11 Chrome 浏览器，彻底避开 trycloudflare 域名的安全策略墙
	headers := make(http.Header)
	headers.Set("Host", host)
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	headers.Set("Forward-Dest", tunnel.Remote)
	headers.Set("Forward-Proto", tunnel.Protocol)

	ws := &Websocket{
		config:   config,
		tunnel:   tunnel,
		wsDialer: wsDialer,
		headers:  headers,
		url:      fmt.Sprintf("%s://%s", config.getScheme(), tunnel.Url),
	}

	go ws.monitorFailoverLoop()
	return ws
}

func (w *Websocket) monitorFailoverLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		latency := w.latencyValue.Load()
		loss := w.lossCounter.Load()

		if (latency > 200) || (loss > 3) {
			log.Warnln("[Failover] Channel quality degraded (RTT: %dms, LossMetric: %d). Performing preventive switchover...", latency, loss)
			w.lossCounter.Store(0)
			newIP := SelectBestIP()
			w.config.CdnIp = newIP
		}
	}
}

func (w *Websocket) createWebsocketStream() (net.Conn, error) {
	start := time.Now()
	wsConn, resp, err := w.wsDialer.Dial(w.url, w.headers)
	
	if err != nil {
		w.lossCounter.Add(1)
		status := "N/A"
		if resp != nil {
			status = resp.Status
		}
		log.Errorln("[Tunnel] WebSocket dial failed. Status: %s | Error: %s", status, err.Error())
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		
		// 故障漂移
		w.config.CdnIp = SelectBestIP()
		wsConn, resp, err = w.wsDialer.Dial(w.url, w.headers)
		if err != nil {
			return nil, err
		}
	}

	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	w.latencyValue.Store(time.Since(start).Milliseconds())

	qosConn := dialer.NewQoSConn(&argo.GorillaConn{Conn: wsConn})
	return qosConn, nil
}
