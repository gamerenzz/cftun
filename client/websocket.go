package client

import (
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
	latencyValue atomic.Int64 // 保存实时链路 RTT (毫秒)
	lossCounter  atomic.Uint32 // 统计异常心跳计数
}

func NewWebsocket(config *Config, tunnel *Tunnel) *Websocket {
	host := strings.Split(tunnel.Url, "/")[0]
	wsDialer := &websocket.Dialer{
		TLSClientConfig: nil,
		Proxy:           http.ProxyFromEnvironment,
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
	headers.Set("User-Agent", "DEV")
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

// 故障预防主动监测循环
func (w *Websocket) monitorFailoverLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		latency := w.latencyValue.Load()
		loss := w.lossCounter.Load()

		// 触发主动预防飘移指标：延迟 > 200ms 持续、或者丢包计数异常
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
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	if err != nil {
		w.lossCounter.Add(1)
		log.Errorln("[Tunnel] WebSocket dial failed. Triggering drift...")
		w.config.CdnIp = SelectBestIP()
		wsConn, resp, err = w.wsDialer.Dial(w.url, w.headers)
		if err != nil {
			return nil, err
		}
	}

	w.latencyValue.Store(time.Since(start).Milliseconds())

	// 包装为带动态 QoS 优先级整形和自研评分统计的连接
	qosConn := dialer.NewQoSConn(&argo.GorillaConn{Conn: wsConn})
	return qosConn, nil
}
