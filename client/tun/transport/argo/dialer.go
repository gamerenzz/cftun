package argo

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fmnx/cftun/client/tun/dialer"
	"github.com/fmnx/cftun/client/tun/metadata"
	"github.com/fmnx/cftun/log"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

type Params struct {
	Scheme      string `json:"scheme"`
	CdnIP       string `json:"cdn-ip"`
	Url         string `json:"url"`
	Port        int    `json:"port"`
	PoolSize    int32  `json:"pool-size"`
	Socks5Proxy string `json:"socks5-proxy"`
}

type Websocket struct {
	params   *Params
	headers  http.Header
	wsDialer *websocket.Dialer
	Url      string
	Address  string

	mu        sync.Mutex
	connCount *atomic.Int32
	stopChan  chan struct{}
	connPool  chan net.Conn

	interactivePool chan net.Conn
}

func NewWebsocket(params *Params) *Websocket {
	hostPath := strings.Split(params.Url, "/")
	host := hostPath[0]

	wsDialer := &websocket.Dialer{
		TLSClientConfig:   &tls.Config{ServerName: host},
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  6 * time.Second,
	}

	address := net.JoinHostPort(params.CdnIP, strconv.Itoa(params.Port))
	wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		var baseDialer proxy.Dialer = dialer

		// 核心安全优化：如果启用了 SOCKS5 代理（Clash/v2rayN）
		if strings.TrimSpace(params.Socks5Proxy) != "" {
			socksDialer, err := proxy.SOCKS5("tcp", params.Socks5Proxy, nil, dialer)
			if err == nil {
				// 极重要：必须直接将“域名目标 (addr)”直传给代理，让代理节点在远端解析！
				// 绝对不要把本地探测出的 Anycast IP 传过去，否则会导致 SNI 混淆报 tls: unrecognized name 错误
				return socksDialer.Dial(network, addr)
			}
		}

		if params.CdnIP != "" {
			return baseDialer.Dial(network, address)
		}
		return baseDialer.Dial(network, addr)
	}

	headers := make(http.Header)
	headers.Set("Host", host)
	headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	ws := &Websocket{
		params:          params,
		wsDialer:        wsDialer,
		headers:         headers,
		Address:         address,
		Url:             fmt.Sprintf("%s://%s", params.Scheme, host),
		connCount:       &atomic.Int32{},
		stopChan:        make(chan struct{}),
		connPool:        make(chan net.Conn, params.PoolSize),
		interactivePool: make(chan net.Conn, 4),
	}

	go ws.preWarmInteractivePool()
	return ws
}

func (w *Websocket) ForceResetPools() {
	w.mu.Lock()
	defer w.mu.Unlock()

	log.Infoln("[Failover] Evicting active connections and clearing pools for migration...")

	for {
		select {
		case conn := <-w.connPool:
			_ = conn.Close()
		default:
			goto resetInteractive
		}
	}

resetInteractive:
	for {
		select {
		case conn := <-w.interactivePool:
			_ = conn.Close()
		default:
			goto rebuild
		}
	}

rebuild:
	w.connCount.Store(0)
	go w.preWarmInteractivePool()
}

func (w *Websocket) preWarmInteractivePool() {
	log.Infoln("[Optimizer] Pre-warming 4 high-speed interactive WebSocket streams to Cloudflare...")
	for i := 0; i < 4; i++ {
		go func() {
			conn, err := w.connect(nil)
			if err == nil {
				select {
				case w.interactivePool <- conn:
				default:
					_ = conn.Close()
				}
			}
		}()
	}
}

func (w *Websocket) replenishInteractive() {
	conn, err := w.connect(nil)
	if err == nil {
		select {
		case w.interactivePool <- conn:
		default:
			_ = conn.Close()
		}
	}
}

func (w *Websocket) Close() {
	close(w.stopChan)
	for conn := range w.connPool {
		_ = conn.Close()
	}
	for conn := range w.interactivePool {
		_ = conn.Close()
	}
}

func (w *Websocket) preDial() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.connCount.Load() >= w.params.PoolSize {
		return
	}
	select {
	case <-w.stopChan:
		return
	default:
		conn, err := w.connect(nil)
		if err != nil {
			return
		}
		select {
		case w.connPool <- conn:
			w.connCount.Add(1)
			return
		default:
			_ = conn.Close()
		}
	}
}

func (w *Websocket) header(metadata *metadata.Metadata) http.Header {
	if metadata == nil {
		return w.headers
	}

	header := make(http.Header, len(w.headers))
	header.Set("Host", w.headers.Get("Host"))
	header.Set("User-Agent", w.headers.Get("User-Agent"))

	destAddr := metadata.DestinationAddress()
	if strings.HasPrefix(destAddr, "172.29.29.") || strings.HasPrefix(destAddr, "198.18.") || strings.HasPrefix(destAddr, "192.168.123.") {
		_, port, err := net.SplitHostPort(destAddr)
		if err == nil {
			destAddr = net.JoinHostPort("127.0.0.1", port)
		}
	}

	header.Set("Forward-Dest", destAddr)
	header.Set("Forward-Proto", metadata.Network.String())
	return header
}

func (w *Websocket) connect(metadata *metadata.Metadata) (net.Conn, error) {
	wsConn, resp, err := w.wsDialer.Dial(w.Url, w.header(metadata))
	
	if err != nil {
		status := "N/A"
		if resp != nil {
			status = resp.Status
		}
		log.Errorln("[Tunnel] Handshake refused by Cloudflare. Status: %s | Error: %s", status, err.Error())
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}

	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	return dialer.NewQoSConn(&GorillaConn{Conn: wsConn}), nil
}

func (w *Websocket) Dial(metadata *metadata.Metadata) (conn net.Conn, headerSent bool, err error) {
	defer func() { go w.preDial() }()

	if metadata != nil && (metadata.Network.String() == "udp" || metadata.DstPort == 5938 || metadata.DstPort == 3389) {
		select {
		case conn = <-w.interactivePool:
			go w.replenishInteractive()
			return conn, false, nil
		default:
			conn, err = w.connect(metadata)
			headerSent = true
			return conn, headerSent, err
		}
	}

	select {
	case <-w.stopChan:
		err = errors.New("websocket has been closed")
		return
	case conn = <-w.connPool:
		w.connCount.Add(-1)
		return
	default:
		conn, err = w.connect(metadata)
		headerSent = true
		return
	}
}
