package dialer

import "net"

// QoSConn 包装原生的 net.Conn，根据每次写入的报文大小动态调整 TOS 优先级
type QoSConn struct {
	net.Conn
	lastTOS int
}

func NewQoSConn(conn net.Conn) *QoSConn {
	return &QoSConn{Conn: conn, lastTOS: -1}
}

func (q *QoSConn) Write(b []byte) (int, error) {
	size := len(b)
	var targetTOS int

	// TeamViewer 流量特征动态分类
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

	return q.Conn.Write(b)
}
