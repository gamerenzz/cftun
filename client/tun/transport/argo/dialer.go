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
	"time"

	"github.com/fmnx/cftun/client/tun/dialer"
	"github.com/fmnx/cftun/client/tun/metadata"
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
	mu       sync.Mutex
}

func NewWebsocket(params *Params) *Websocket {
	hostPath := strings.Split(params.Url, "/")
	host := hostPath[0]

	wsDialer := &websocket.Dialer{
		TLSClientConfig:   &tls.Config{ServerName: host},
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  6 * time.Second, // 宽裕的重传超时
	}

	address := net.JoinHostPort(params.CdnIP, strconv.Itoa(params.Port))
	wsDialer.NetDial = func(network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		var baseDialer proxy.Dialer = dialer

		if strings.TrimSpace(params.Socks5Proxy) != "" {
			socksDialer, err := proxy.SOCKS5("tcp", params.Socks5Proxy, nil, dialer)
			if err == nil {
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
		params:   params,
		wsDialer: wsDialer,
		headers:  headers,
		Address:  address,
		Url:      fmt.Sprintf("%s://%s", params.Scheme, host),
	}
	return ws
}

// ForceResetPools 在按需模式下无需任何操作，保持空接口以兼容外部路由
func (w *Websocket) ForceResetPools() {
	// No-op
}

func (w *Websocket) Close() {
	// No-op
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
		return nil, fmt.Errorf("Cloudflare Handshake refused. Status: %s | Error: %w", status, err)
	}

	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	return dialer.NewQoSConn(&GorillaConn{Conn: wsConn}), nil
}

func (w *Websocket) Dial(metadata *metadata.Metadata) (conn net.Conn, headerSent bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 按需实时、零额外开销建连，彻底规避空闲保活机制
	conn, err = w.connect(metadata)
	headerSent = true
	return conn, headerSent, err
}
