package conn

import (
    "context"
    "io"
    "net"
    "sync"
    "time"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const bufferSize = 20 << 10;

var buffers = sync.Pool {
    New: func() interface {} {
        return make([]byte, bufferSize)
    },
}

type TCPConnection interface {
	net.Conn
	ID() *stack.TransportEndpointID
}

func handleTCP(localConn TCPConnection) {
    defer localConn.Close()

    id := localConn.ID()

    targetConn, err := dial(net.IP(id.LocalAddress), id.LocalPort)

    if err != nil {
        log.Warningf("[TCP] Dial %v:%v: %v", id.LocalAddress, id.LocalPort, err)
        return
    }

    relay(localConn, targetConn)
}

func dial(ip net.IP, port uint16) (net.Conn, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
    defer cancel()
    return DialTCP(ctx, ip, port)
}

func relay(left, right net.Conn) {
    wg := sync.WaitGroup {}
    wg.Add(2)

    go func() {
        defer wg.Done()
        buf := buffers.Get().([]byte)
        defer buffers.Put(buf)

        io.CopyBuffer(right, left, buf)

        right.SetReadDeadline(time.Now().Add(5 * time.Second))
    }()

    go func() {
        defer wg.Done()
        buf := buffers.Get().([]byte)
        defer buffers.Put(buf)

        io.CopyBuffer(left, right, buf)

        left.SetReadDeadline(time.Now().Add(5 * time.Second))
    }()

    wg.Wait()
}

