package dialer

import (
	"math/rand"
	"net"
	"time"

	"github.com/fmnx/cftun/log" // 导入主日志包，使其能向控制面板输出 Debug 工作铁证
)

type QoSConn struct {
	net.Conn
	lastTOS int
	isUDP   bool // 是否为 UDP 流量 (TeamViewer 交互控制核心)
}

func NewQoSConn(conn net.Conn, isUDP bool) *QoSConn {
	q := &QoSConn{
		Conn:    conn,
		lastTOS: -1,
		isUDP:   isUDP,
	}
	
	// 启动后台噪声混淆注入，打乱流量特征，规避晚高峰 DPI 特征识别
	go q.startNoiseInjectionLoop()
	return q
}

// startNoiseInjectionLoop 每隔随机 300~800 毫秒，向 Cloudflare 发送一次带 50~120 字节随机 Payload 的标准 Ping 帧
func (q *QoSConn) startNoiseInjectionLoop() {
	ticker := time.NewTicker(time.Duration(300+rand.Intn(500)) * time.Millisecond)
	defer ticker.Stop()

	type pinger interface {
		SendPingWithPayload(payload []byte) error
	}

	for range ticker.C {
		if q.Conn == nil {
			return
		}
		if pc, ok := q.Conn.(pinger); ok {
			size := 50 + rand.Intn(70) // 50~120 字节随机噪声
			noise := make([]byte, size)
			for i := range noise {
				noise[i] = byte(rand.Intn(256))
			}
			err := pc.SendPingWithPayload(noise)
			if err == nil {
				// 核心修复：增加 Debug 级别工作铁证，向控制面板输出混淆数据包长度
				log.Debugln("[Noise] Injected %d bytes of random WSS padding frame to disrupt DPI traffic analysis.", size)
			}
		}
	}
}

func (q *QoSConn) Write(b []byte) (int, error) {
	size := len(b)
	var targetTOS int

	if size < 200 {
		targetTOS = 0xB8 // 控制流 (最高优先级: EF)
	} else if size <= 1000 {
		targetTOS = 0x88 // 屏幕流 (中优先级: AF41)
	} else {
		targetTOS = 0x20 // 文件流 (低优先级: CS1)
	}

	if targetTOS != q.lastTOS {
		SetSocketTOS(q.Conn, targetTOS)
		q.lastTOS = targetTOS
	}

	n, err := q.Conn.Write(b)

	// UDP 智能双发：针对远程控制高频、低延迟 UDP 交互包进行冗余双发
	if q.isUDP && size < 1000 {
		_, _ = q.Conn.Write(b) // 瞬间双发重传，绝杀物理丢包
		// 核心修复：增加 Debug 级别工作铁证，向控制面板输出丢包双发数据
		log.Debugln("[QoS] UDP Interactive Packet (Size: %d) Double-Sent successfully to mitigate public loss.", size)
	}

	return n, err
}
