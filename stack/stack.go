package stack

import (
    "fmt"
    "net"

    "github.com/google/gopacket/routing"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/header"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
    "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
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

    info := func(id stack.TransportEndpointID) {
        r, err := routing.New()
        if err != nil { panic(err) }
        iface, gw, preferred, err := r.Route(net.ParseIP(id.LocalAddress.String()))
        if err != nil { panic(err) }
        log.Infof("routing: iface %s, gw %s, addr %s", iface.Name, gw.String(), preferred.String())
    }

    tcpForwarder := tcp.NewForwarder(s.Stack, 0, 2048, func(r *tcp.ForwarderRequest) {
        log.Infof("tcp connection: %v", r.ID())
        info(r.ID())
        r.Complete(true)
    })
    s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

    udpHandlePacket := func(id stack.TransportEndpointID, _ *stack.PacketBuffer) bool {
        log.Infof("udp packet: %v", id)
        info(id)
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
