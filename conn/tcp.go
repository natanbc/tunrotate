package conn

import (
    "net"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

var TcpConnectTimeout = 10 * time.Second
var TcpWaitTimeout = 5 * time.Second

type TCPConnectionRequest interface {
    ConnectLocal() (net.Conn, error)
    ID() *stack.TransportEndpointID
}

func handleTCP(connReq TCPConnectionRequest) {
    id := connReq.ID()

    targetConn, err := dial("tcp", TcpConnectTimeout, net.IP(id.LocalAddress), id.LocalPort)

    if err != nil {
        log.Warningf("[TCP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }
    defer targetConn.Close()

    localConn, err := connReq.ConnectLocal()
    if err != nil {
        log.Warningf("[TCP] Failed to connect local side %v: %v", id, err)
        return
    }

    defer localConn.Close()

    relay(localConn, targetConn, TcpWaitTimeout)
    log.Debugf("[TCP] Closed connection %v:%v->%v:%v", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
}

