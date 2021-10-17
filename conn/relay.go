package conn

import (
    "io"
    "net"
    "sync"
    "time"
)

func relay(left, right net.Conn, waitTimeout time.Duration) {
    wg := sync.WaitGroup {}
    wg.Add(2)

    go func() {
        defer wg.Done()
        buf := acquireBuffer()
        defer releaseBuffer(buf)

        io.CopyBuffer(right, left, buf)

        right.SetReadDeadline(time.Now().Add(waitTimeout))
    }()

    go func() {
        defer wg.Done()
        buf := acquireBuffer()
        defer releaseBuffer(buf)

        io.CopyBuffer(left, right, buf)

        left.SetReadDeadline(time.Now().Add(waitTimeout))
    }()

    wg.Wait()
}

