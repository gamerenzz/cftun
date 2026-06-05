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

		// P2 真·连接漂移式 Failover
		if rating == "Poor (较差)" {
			log.Warnln("[Failover] Quality degraded to Poor. Initiating active connection migration...")
			w.lossCounter.Store(0)
			w.latencyValue.Store(0)
			
			// 1. 在本地更新最优 Anycast IP
			newIP := SelectBestIP(w.config.GlobalUrl)
			w.config.CdnIp = newIP

			// 2. 强行驱逐、断开并重建当前的物理连接池，将旧物理连接斩断，实现无缝热迁移
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
