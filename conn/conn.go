package conn

var tcpQueue = make(chan TCPConnection)
var udpQueue = make(chan UDPConnection)

func NewTCP(c TCPConnection) {
    tcpQueue <- c
}

func NewUDP(c UDPConnection) {
    udpQueue <- c
}

func init() {
    go func() {
        for connection := range udpQueue {
            go handleUDP(connection)
        }
    }()

    go func() {
        for connection := range tcpQueue {
            go handleTCP(connection)
        }
    }()
}

