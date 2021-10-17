package conn

import (
    "runtime"

    "gvisor.dev/gvisor/pkg/log"
)

const maxUDPQueueSize = 1 << 9

var tcpQueue = make(chan TCPConnection)
var udpQueue = make(chan UDPPacket, maxUDPQueueSize)

func NewTCP(c TCPConnection) {
    tcpQueue <- c
}

func SendUDP(p UDPPacket) {
    select {
    case udpQueue <- p:
    default:
        log.Warningf("UDP queue full, dropping packet")
        p.Drop()
    }
}

func init() {
    go func() {
        udpWorkers := runtime.NumCPU()
        if udpWorkers < 4 {
            udpWorkers = 4
        }

        for i := 0; i < udpWorkers; i++ {
            q := udpQueue
            go func() {
                for packet := range q {
                    handleUDP(packet)
                }
            }()
        }

        for connection := range tcpQueue {
            go handleTCP(connection)
        }
    }()
}

