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

	// 真·高活性控制交互连接池（常备 4 个完全就绪连接）
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

	// 启动时，主动在后台预热建立 4 个高活性控制专用连接，消灭建连延迟
	go ws.preWarmInteractivePool()
	return ws
}

// 预热 4 条完全就绪的 WSS 链路，随时待命
func (w *Websocket) preWarmInteractivePool() {
	log.Infoln("[Optimizer] Pre-warming 4 high-speed interactive WebSocket streams to Cloudflare...")
	for i := 0; i < 4; i++ {
		go func() {
			conn, err := w.connect(nil)
			if err == nil {
				select {
				case w.interactivePool <- conn:
					// 成功置入常备队列
				default:
					_ = conn.Close()
				}
			}
		}()
	}
}

// 自动补货机制，维持 4 个常备就绪连接的动态平衡
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

	// 真正的预连接调度：控制小包流在 0 毫秒内瞬间取用已经建立好并完成握手的常备连接！
	if metadata != nil && (metadata.Network.String() == "udp" || metadata.DstPort == 5938 || metadata.DstPort == 3389) {
		select {
		case conn = <-w.interactivePool:
			// 自动异步补货，确保池子里永远有 4 个待命
			go w.replenishInteractive()
			return conn, false, nil
		default:
			// 极其罕见的瞬时耗尽降级备用
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
