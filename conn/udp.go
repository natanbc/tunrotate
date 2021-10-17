package conn

import (
    "net"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type UDPPacket interface {
    Data() []byte

    Drop()

    ID() *stack.TransportEndpointID

    LocalAddr() net.Addr

    RemoteAddr() net.Addr

    WriteBack([]byte, net.Addr) (int, error)
}

func handleUDP(_ UDPPacket) {

}

