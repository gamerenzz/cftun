package engine

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"

	"github.com/fmnx/cftun/client/tun/buffer"
	"github.com/fmnx/cftun/client/tun/core"
	"github.com/fmnx/cftun/client/tun/core/adapter"
	"github.com/fmnx/cftun/client/tun/core/device"
	"github.com/fmnx/cftun/client/tun/core/device/fdbased"
	"github.com/fmnx/cftun/client/tun/core/device/iobased"
	"github.com/fmnx/cftun/client/tun/core/device/tun"
	"github.com/fmnx/cftun/client/tun/core/option"
	"github.com/fmnx/cftun/client/tun/dialer"
	"github.com/fmnx/cftun/client/tun/log"
	"github.com/fmnx/cftun/client/tun/proxy"
	"github.com/fmnx/cftun/client/tun/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	Mu sync.Mutex

	Device    device.Device
	Stack     *stack.Stack
	ArgoProxy *proxy.Argo
)

func Stop() {
	if err := stop(); err != nil {
		log.Fatalf("[ENGINE] failed to stop: %v", err)
	}
}

func stop() (err error) {
	Mu.Lock()
	if Device != nil {
		Device.Close()
	}
	if ArgoProxy != nil {
		go ArgoProxy.Close()
	}
	if Stack != nil {
		Stack.Close()
		Stack.Wait()
	}
	Mu.Unlock()
	return nil
}

// parseIPv4UDPPorts 零内存分配的高效 IP/UDP 报文头解析器
func parseIPv4UDPPorts(packet []byte) (srcPort, dstPort uint16, isUDP bool) {
	if len(packet) < 28 { // IP头(20字节) + UDP头(8字节)
		return 0, 0, false
	}
	version := packet[0] >> 4
	if version != 4 {
		return 0, 0, false // 仅加速最核心的 IPv4 远程控制流
	}
	protocol := packet[9]
	if protocol != 17 { // 判定是否是 UDP 协议 (TeamViewer 等控制核心基于 UDP)
		return 0, 0, false
	}
	headerLen := int(packet[0]&0x0f) * 4
	if len(packet) < headerLen+8 {
		return 0, 0, false
	}
	srcPort = binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
	dstPort = binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
	return srcPort, dstPort, true
}

func HandleNetStack(argoProxy *proxy.Argo, device, interfaceName, logLevel string, mtu int) (err error) {
	ArgoProxy = argoProxy
	buffer.RelayBufferSize = mtu
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	log.SetLogger(log.Must(log.NewLeveled(level)))

	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return err
		}
		dialer.DefaultInterfaceName.Store(iface.Name)
		dialer.DefaultInterfaceIndex.Store(int32(iface.Index))
		log.Infof("[DIALER] bind to interface: %s", interfaceName)
	}

	transport := tunnel.New(argoProxy)
	transport.ProcessAsync()

	// 真·FastPath 拦截拦截挂载实现
	iobased.FastPathHook = func(packet []byte) bool {
		srcPort, dstPort, isUDP := parseIPv4UDPPorts(packet)
		if isUDP && (dstPort == 5938 || dstPort == 3389 || dstPort == 7070 || srcPort == 5938) {
			// 成功判定为远程桌面专属控制包。从网卡读取后，直接通过 FastPath 送往优选 Proxy 通道
			// 绕过了 gVisor 对大流量/高频包进行虚拟 IP 解析、滑动窗口排序和用户态 Socket 转换的昂贵开销
			return true 
		}
		return false // 其他非关键普通流量继续通过 gVisor 协议栈，保持兼容性
	}

	if Device, err = parseDevice(device, uint32(mtu)); err != nil {
		log.Fatalf(err.Error(), "\n")
		return
	}

	var multicastGroups []netip.Addr

	var opts []option.Option

	if Stack, err = core.CreateStack(&core.Config{
		LinkEndpoint:     Device,
		TransportHandler: transport,
		MulticastGroups:  multicastGroups,
		Options:          opts,
	}); err != nil {
		return
	}

	log.Infof(
		"[STACK] %s://%s <-> %s -> %s",
		Device.Type(), Device.Name(),
		argoProxy.Host(), argoProxy.Addr(),
	)
	return nil
}
