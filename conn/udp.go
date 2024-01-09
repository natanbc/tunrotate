package conn

import (
    "net"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

var UdpConnectTimeout = 5 * time.Second
var UdpWaitTimeout = 5 * time.Second

type UDPConnection interface {
    net.Conn
    ID() *stack.TransportEndpointID
}

func handleUDP(localConn UDPConnection) {
    defer localConn.Close()

    id := localConn.ID()

    targetConn, err := dial("udp", UdpConnectTimeout, net.ParseIP(id.LocalAddress.String()), id.LocalPort)
    if err != nil {
        log.Warningf("[UDP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }
    defer targetConn.Close()

    relay(localConn, targetConn, UdpWaitTimeout)
    log.Debugf("[UDP] Closed connection %v:%v->%v:%v", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
}

