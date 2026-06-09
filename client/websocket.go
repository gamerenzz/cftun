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
	"github.com/fmnx/cftun/client/tun/engine"
	"github.com/fmnx/cftun/client/tun/transport/argo"
	"github.com/fmnx/cftun/log"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
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
	
	wsDialer := &websocket.Dialer{
		TLSClientConfig:   &tls.Config{ServerName: host},
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  6 * time.Second,
	}

	wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		var baseDialer proxy.Dialer = dialer

		// 核心升级：如果后台配置了本地 SOCKS5 代理（Clash），主通道握手将直接无缝走专线中转
		if strings.TrimSpace(config.Socks5Proxy) != "" {
			socksDialer, err := proxy.SOCKS5("tcp", config.Socks5Proxy, nil, dialer)
			if err == nil {
				baseDialer = socksDialer
			}
		}

		if config.CdnIp != "" {
			return baseDialer.Dial(network, config.getAddress())
		}
		return baseDialer.Dial(network, addr)
	}

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

	go ws.monitorLinkQualityAndFailover()
	return ws
}

func (w *Websocket) monitorLinkQualityAndFailover() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastLatency int64

	for range ticker.C {
		if !isRunning {
			continue
		}

		latency := w.latencyValue.Load()
		loss := w.lossCounter.Load()

		if latency == 0 {
			continue
		}

		jitter := latency - lastLatency
		if jitter < 0 {
			jitter = -jitter
		}
		lastLatency = latency

		rating := "Excellent (极佳)"
		if latency > 180 || loss > 1 || jitter > 25 {
			rating = "Good (良好)"
		}
		if latency > 250 || loss > 2 || jitter > 50 {
			rating = "Poor (较差)"
		}

		log.Infoln("[Monitor] Active Tunnel Status: RTT: %dms | Jitter: %dms | LossMetric: %d | Rating: %s",
			latency, jitter, loss, rating)

		if rating == "Poor (较差)" {
			log.Warnln("[Failover] Quality degraded to Poor. Initiating active connection migration...")
			w.lossCounter.Store(0)
			w.latencyValue.Store(0)
			
			newIP := SelectBestIP(w.config.GlobalUrl)
			w.config.CdnIp = newIP

			if engine.ArgoProxy != nil {
				engine.ArgoProxy.MigratePools()
			}
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
		
		w.config.CdnIp = SelectBestIP(w.config.GlobalUrl)
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
