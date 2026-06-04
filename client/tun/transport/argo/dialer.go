package argo

import (
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

	// V2：增加多流相互独立的高速控制专线，防止队头阻塞
	interactivePool chan net.Conn
}

func NewWebsocket(params *Params) *Websocket {
	hostPath := strings.Split(params.Url, "/")
	host := hostPath[0]

	wsDialer := &websocket.Dialer{
		TLSClientConfig:   nil,
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  3 * time.Second,
		ReadBufferSize:    32 << 10,
		WriteBufferSize:   32 << 10,
		EnableCompression: false, // 远程桌面自带高度压缩，二次压缩反而加重开销
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
	headers.Set("User-Agent", "DEV")

	ws := &Websocket{
		params:          params,
		wsDialer:        wsDialer,
		headers:         headers,
		Address:         address,
		Url:             fmt.Sprintf("%s://%s", params.Scheme, host),
		connCount:       &atomic.Int32{},
		stopChan:        make(chan struct{}),
		connPool:        make(chan net.Conn, params.PoolSize),
		interactivePool: make(chan net.Conn, 4), // 建立4个预备交互专线
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
	header.Set("User-Agent", "DEV")
	header.Set("Forward-Dest", metadata.DestinationAddress())
	header.Set("Forward-Proto", metadata.Network.String())
	return header
}

func (w *Websocket) connect(metadata *metadata.Metadata) (net.Conn, error) {
	wsConn, resp, err := w.wsDialer.Dial(w.Url, w.header(metadata))
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	// 针对交互专线及常规传输流统一包装，利用 QoS 自动分包器分配优先级
	return dialer.NewQoSConn(&GorillaConn{Conn: wsConn}), nil
}

func (w *Websocket) Dial(metadata *metadata.Metadata) (conn net.Conn, headerSent bool, err error) {
	defer func() { go w.preDial() }()

	// V2：对于交互控制小包流（UDP信令或特定端口），调度到独立的交互专用连接上发送，免受屏幕刷新等大包排队影响
	if metadata != nil && (metadata.Network.String() == "udp" || metadata.DstPort == 5938 || metadata.DstPort == 3389) {
		select {
		case conn = <-w.interactivePool:
			return conn, false, nil
		default:
			// 如果缓存专线不够，现场开辟控制专线以确保低延迟
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
