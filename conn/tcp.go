package conn

import (
    "net"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

var TcpConnectTimeout = 10 * time.Second
var TcpWaitTimeout = 5 * time.Second

type TCPConnection interface {
    net.Conn
    ID() *stack.TransportEndpointID
}

func handleTCP(localConn TCPConnection) {
    defer localConn.Close()

    id := localConn.ID()

    targetConn, err := dial("tcp", TcpConnectTimeout, net.IP(id.LocalAddress), id.LocalPort)

    if err != nil {
        log.Warningf("[TCP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }
    defer targetConn.Close()

    relay(localConn, targetConn, TcpWaitTimeout)
    log.Debugf("[TCP] Closed connection %v:%v->%v:%v", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
}

