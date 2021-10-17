package stack

import (
    "fmt"
    "net"

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
        var wq waiter.Queue
        id := r.ID()
        log.Debugf("tcp connection: %v", id)

        ep, err := r.CreateEndpoint(&wq)
        if err != nil {
            log.Warningf("unable to create tcp endpoint: %v", err)
            r.Complete(true)
            return
        }
        r.Complete(false)

        connection := &tcpConnection {
            Conn: gonet.NewTCPConn(&wq, ep),
            id: &id,
        }

        conn.NewTCP(connection)
    })
    s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

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
    net.Conn
    id *stack.TransportEndpointID
}

func (c *tcpConnection) ID() *stack.TransportEndpointID {
	return c.id
}

type udpConnection struct {
    net.Conn
    id *stack.TransportEndpointID
}

func (c *udpConnection) ID() *stack.TransportEndpointID {
    return c.id
}

