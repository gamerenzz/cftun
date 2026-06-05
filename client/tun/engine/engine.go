package engine

import (
	"net"
	"net/netip"
	"sync"

	"github.com/fmnx/cftun/client/tun/buffer"
	"github.com/fmnx/cftun/client/tun/core"
	"github.com/fmnx/cftun/client/tun/core/device"
	"github.com/fmnx/cftun/client/tun/core/device/fdbased"
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
