package stack

import (
    "fmt"
    "net"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
    "gvisor.dev/gvisor/pkg/tcpip/buffer"
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

    udpHandlePacket := func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
        log.Debugf("udp packet: %v", id)

        udpHdr := header.UDP(pkt.TransportHeader().View())
        if int(udpHdr.Length()) > pkt.Data().Size() + header.UDPMinimumSize {
            return true
        }

        if !verifyChecksum(udpHdr, pkt) {
            return true
        }

        packet := &udpPacket {
            s:        s,
            id:       &id,
            data:     pkt.Data().ExtractVV(),
            nicID:    pkt.NICID,
            netHdr:   pkt.Network(),
            netProto: pkt.NetworkProtocolNumber,
        }

        conn.SendUDP(packet)

        return true
    }
    s.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandlePacket)

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

type udpPacket struct {
    s        *Stack
    id       *stack.TransportEndpointID
    data     buffer.VectorisedView
    nicID    tcpip.NICID
    netHdr   header.Network
    netProto tcpip.NetworkProtocolNumber
}

func (p *udpPacket) Data() []byte {
    return p.data.ToView()
}

func (p *udpPacket) Drop() {}

func (p *udpPacket) ID() *stack.TransportEndpointID {
    return p.id
}

func (p *udpPacket) LocalAddr() net.Addr {
    return &net.UDPAddr {
        IP: net.IP(p.id.LocalAddress),
        Port: int(p.id.LocalPort),
    }
}

func (p *udpPacket) RemoteAddr() net.Addr {
    return &net.UDPAddr {
        IP: net.IP(p.id.RemoteAddress),
        Port: int(p.id.RemotePort),
    }
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
    v := buffer.View(b)
    if len(v) > header.UDPMaximumPacketSize {
        return -1, fmt.Errorf("%s", &tcpip.ErrMessageTooLong{})
    }

    var localAddress tcpip.Address
    var localPort uint16

    if udpAddr, ok := addr.(*net.UDPAddr); !ok {
        localAddress = p.netHdr.DestinationAddress()
        localPort = p.id.LocalPort
    } else if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
        localAddress = tcpip.Address(ipv4)
        localPort = uint16(udpAddr.Port)
    } else {
        localAddress = tcpip.Address(udpAddr.IP)
        localPort = uint16(udpAddr.Port)
    }

    route, err := p.s.FindRoute(p.nicID, localAddress, p.netHdr.SourceAddress(), p.netProto, false)
    if err != nil {
        return -1, fmt.Errorf("%#v no route: %s", p.id, err)
    }
    defer route.Release()

    data := v.ToVectorisedView()
    if err = sendUDP(route, data, localPort, p.id.RemotePort, true /* no checksum */); err != nil {
        return -1, fmt.Errorf("failed to send udp packet: %v", err)
    }

    return data.Size(), nil
}

func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, noChecksum bool) tcpip.Error {
    pkt := stack.NewPacketBuffer(stack.PacketBufferOptions {
        ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
        Data:               data,
    })

    udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
    pkt.TransportProtocolNumber = udp.ProtocolNumber

    length := uint16(pkt.Size())
    udpHdr.Encode(&header.UDPFields {
        SrcPort: localPort,
        DstPort: remotePort,
        Length:  length,
    })

    if r.RequiresTXTransportChecksum() && (!noChecksum || r.NetProto() == header.IPv6ProtocolNumber) {
        checksum := r.PseudoHeaderChecksum(udp.ProtocolNumber, length)
        for _, v := range data.Views() {
            checksum = header.Checksum(v, checksum)
        }
        udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum))
    }

    ttl := r.DefaultTTL()

    return r.WritePacket(stack.NetworkHeaderParams {
        Protocol: udp.ProtocolNumber,
        TTL:      ttl,
        TOS:      0,
    }, pkt)
}

func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool {
    if !pkt.RXTransportChecksumValidated && (hdr.Checksum() != 0 || pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber) {
        netHdr := pkt.Network()
        checksum := header.PseudoHeaderChecksum(udp.ProtocolNumber, netHdr.DestinationAddress(), netHdr.SourceAddress(), hdr.Length())
        for _, v := range pkt.Data().Views() {
            checksum = header.Checksum(v, checksum)
        }
        return hdr.CalculateChecksum(checksum) == 0xffff
    }
    return true
}

