package conn

import (
    "net"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const tcpConnectTimeout = 5 * time.Second
const tcpWaitTimeout = 5 * time.Second

type TCPConnection interface {
	net.Conn
	ID() *stack.TransportEndpointID
}

func handleTCP(localConn TCPConnection) {
    defer localConn.Close()

    id := localConn.ID()

    targetConn, err := dial("tcp", tcpConnectTimeout, net.IP(id.LocalAddress), id.LocalPort)

    if err != nil {
        log.Warningf("[TCP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }

    relay(localConn, targetConn, tcpWaitTimeout)
}

