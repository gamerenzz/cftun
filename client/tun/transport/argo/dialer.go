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
)

type Params struct {
	Scheme   string `json:"scheme"`
	CdnIP    string `json:"cdn-ip"`
	Url      string `json:"url"`
	Port     int    `json:"port"`
	PoolSize int32  `json:"pool-size"`
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
		HandshakeTimeout:  3 * time.Second,
		ReadBufferSize:    32 << 10,
		WriteBufferSize:   32 << 10,
		EnableCompression: false,
	}

	address := net.JoinHostPort(params.CdnIP, strconv.Itoa(params.Port))
	wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
		if params.CdnIP != "" {
			return dialer.Dial(network, address)
		}
		return dialer.Dial(network, addr)
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
	return ws
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

	// 核心架构升级：如果是虚拟网卡中继路由产生的 IP 流量（如 198.18.x.x）
	// 被控端本地无法寻路，因此客户端自动将其重写为 127.0.0.1 转发给被控端本地回环
	destAddr := metadata.DestinationAddress()
	if strings.HasPrefix(destAddr, "198.18.") || strings.HasPrefix(destAddr, "192.168.123.") {
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
