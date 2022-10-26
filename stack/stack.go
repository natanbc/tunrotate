package stack

import (
    "fmt"
    "net"
    "time"
    "sync"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
    "gvisor.dev/gvisor/pkg/tcpip/header"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
    "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
    "gvisor.dev/gvisor/pkg/waiter"

    "github.com/natanbc/tunrotate/conn"
)

type Stack struct {
    *stack.Stack
    nicID tcpip.NICID
}

func New(ep stack.LinkEndpoint) (*Stack, error) {
    s := &Stack {
        Stack: stack.New(stack.Options{
            NetworkProtocols:   []stack.NetworkProtocolFactory { ipv4.NewProtocol, ipv6.NewProtocol },
            TransportProtocols: []stack.TransportProtocolFactory { tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6 },
        }),
        nicID: 0x01,
    }

    s.SetRouteTable([]tcpip.Route{
        {
            Destination: header.IPv4EmptySubnet,
            NIC:         s.nicID,
        },
        {
            Destination: header.IPv6EmptySubnet,
            NIC:         s.nicID,
        },
    })

    tcpForwarder := tcp.NewForwarder(s.Stack, 0, 2048, func(r *tcp.ForwarderRequest) {
        id := r.ID()
        log.Debugf("tcp connection: %v", id)

        connection := &tcpConnection {
            id: &id,
            request: r,
            start: time.Now(),
        }

        conn.NewTCP(connection)
    })
    s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

    {
        opt := tcpip.TCPSACKEnabled(true)
        s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
    }
    {
        opt := tcpip.TCPModerateReceiveBufferOption(true)
        s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
    }

    bufSize := 4 * 1024 * 1024
    {
        opt := tcpip.TCPReceiveBufferSizeRangeOption { Min: 1, Default: bufSize, Max: bufSize }
        s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
    }
    {
        opt := tcpip.TCPSendBufferSizeRangeOption { Min: 1, Default: bufSize, Max: bufSize }
        s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
    }

    udpForwarder := udp.NewForwarder(s.Stack, func(r *udp.ForwarderRequest) {
        var wq waiter.Queue
        id := r.ID()
        log.Debugf("udp packet: %v", id)

        ep, err := r.CreateEndpoint(&wq)
        if err != nil {
            log.Warningf("unable to create udp endpoint: %v", err)
            return
        }

        connection := &udpConnection {
            Conn: gonet.NewUDPConn(s.Stack, &wq, ep),
            id:   &id,
        }

        conn.NewUDP(connection)
    })
    s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

    if err := s.CreateNIC(s.nicID, ep); err != nil {
        return nil, fmt.Errorf("Unable to create NIC: %s", err)
    }
    if err := s.SetPromiscuousMode(s.nicID, true); err != nil {
        return nil, fmt.Errorf("Unable to enable promiscuous mode: %s", err)
    }
    if err := s.SetSpoofing(s.nicID, true); err != nil {
        return nil, fmt.Errorf("Unable to enable spoofing: %s", err)
    }

    return s, nil
}

type tcpConnection struct {
    start time.Time
    id *stack.TransportEndpointID
    requestLock sync.Mutex
    request *tcp.ForwarderRequest
}

func (c *tcpConnection) ID() *stack.TransportEndpointID {
	return c.id
}

func (c *tcpConnection) ConnectLocal() (net.Conn, error) {
    c.requestLock.Lock()
    defer c.requestLock.Unlock()

    r := c.request
    if r == nil {
        panic(fmt.Sprintf("Attempt to create multiple local connections for %v", c.id))
    }
    c.request = nil

    log.Debugf("Completing tcp connection %v after %v", c.id, time.Now().Sub(c.start))

    var wq waiter.Queue
    ep, err := r.CreateEndpoint(&wq)
    if err != nil {
        r.Complete(true)
        return nil, fmt.Errorf("Unable to create endpoint: %v", err)
    }
    r.Complete(false)

    return gonet.NewTCPConn(&wq, ep), nil
}

type udpConnection struct {
    net.Conn
    id *stack.TransportEndpointID
}

func (c *udpConnection) ID() *stack.TransportEndpointID {
    return c.id
}

