package argo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	gobwas "github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

const (
	defaultPongWait = 60 * time.Second
	defaultPingPeriod = (defaultPongWait * 9) / 10
	PingPeriodContextKey = PingPeriodContext("pingPeriod")
)

type PingPeriodContext string

type GorillaConn struct {
	*websocket.Conn
	readBuf bytes.Buffer
	writeMu sync.Mutex
}

func (c *GorillaConn) Read(p []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	_, message, err := c.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	copied := copy(p, message)
	c.readBuf.Write(message[copied:])
	return copied, nil
}

func (c *GorillaConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *GorillaConn) SendPing() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.WriteMessage(websocket.PingMessage, []byte{})
}

// SendPingWithPayload 允许发送带随机载荷的混淆 Ping 帧，使用写互斥锁保护，防止通道崩溃
func (c *GorillaConn) SendPingWithPayload(payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.WriteMessage(websocket.PingMessage, payload)
}

func (c *GorillaConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return fmt.Errorf("error setting read deadline: %w", err)
	}
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return fmt.Errorf("error setting write deadline: %w", err)
	}
	return nil
}

type Conn struct {
	rw        io.ReadWriter
	log       *zerolog.Logger
	writeLock sync.Mutex
	done      bool
}

func (c *Conn) Read(reader []byte) (int, error) {
	data, err := wsutil.ReadClientBinary(c.rw)
	if err != nil {
		return 0, err
	}
	return copy(reader, data), nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	if c.done {
		return 0, errors.New("write to closed websocket connection")
	}
	if err := wsutil.WriteServerBinary(c.rw, p); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *Conn) pinger(ctx context.Context) {
	pongMessge := wsutil.Message{
		OpCode:  gobwas.OpPong,
		Payload: []byte{},
	}

	ticker := time.NewTicker(c.pingPeriod(ctx))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			done, err := c.ping()
			if done {
				return
			}
			if err != nil {
				c.log.Debug().Err(err).Msgf("failed to write ping message")
			}
			if err := wsutil.HandleClientControlMessage(c.rw, pongMessge); err != nil {
				c.log.Debug().Err(err).Msgf("failed to write pong message")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Conn) ping() (bool, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	if c.done {
		return true, nil
	}

	return false, wsutil.WriteServerMessage(c.rw, gobwas.OpPing, []byte{})
}

func (c *Conn) pingPeriod(ctx context.Context) time.Duration {
	if val := ctx.Value(PingPeriodContextKey); val != nil {
		if period, ok := val.(time.Duration); ok {
			return period
		}
	}
	return defaultPingPeriod
}

func (c *Conn) Close() {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	c.done = true
}
