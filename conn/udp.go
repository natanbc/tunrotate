package conn

import (
    "net"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const udpConnectTimeout = 5 * time.Second
const udpWaitTimeout = 5 * time.Second

type UDPConnection interface {
	net.Conn
	ID() *stack.TransportEndpointID
}

func handleUDP(localConn UDPConnection) {
    defer localConn.Close()

    id := localConn.ID()

    targetConn, err := dial("udp", udpConnectTimeout, net.IP(id.LocalAddress), id.LocalPort)
    if err != nil {
        log.Warningf("[UDP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }
    defer targetConn.Close()

    relay(localConn, targetConn, udpWaitTimeout)
    log.Debugf("[UDP] Connection %v:%v->%v:%v closed", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
}

