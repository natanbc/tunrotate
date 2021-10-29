package conn

var tcpQueue = make(chan TCPConnectionRequest)
var udpQueue = make(chan UDPConnection)

func NewTCP(c TCPConnectionRequest) {
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

