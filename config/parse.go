package config

import (
    "encoding/json"
    "fmt"
    "net"
    "strings"
    "time"
)

func (d *Duration) UnmarshalJSON(data []byte) error {
    var v string
    if err := json.Unmarshal(data, &v); err != nil {
        return err
    }
    dur, err := time.ParseDuration(v)
    if err != nil {
        return err
    }
    *d = Duration(dur)
    return nil
}

func (r *Route) UnmarshalJSON(data []byte) error {
    j := routeJson {}
    if err := json.Unmarshal(data, &j); err != nil {
        return err
    }

    r.Destination = j.Destination

    switch strings.ToLower(j.Via) {
    case "tun":
        r.Via = ViaTun
    case "address":
        r.Via = ViaAddress
        r.Source = (net.IP)(j.Source)

        dstV4 := r.Destination.IP.To4() != nil
        srcV4 := r.Source.To4() != nil
        if dstV4 && !srcV4 {
            return fmt.Errorf("Cannot route to an ipv4 address from an ipv6 address")
        } else if !dstV4 && srcV4 {
            return fmt.Errorf("Cannot route to an ipv6 address from an ipv4 address")
        }
    default:
        return fmt.Errorf("Unknown via '%s'", j.Via)
    }

    return nil
}

func (p *Policy) UnmarshalJSON(data []byte) error {
    j := policyJson {}
    if err := json.Unmarshal(data, &j); err != nil {
        return err
    }

    ifs := make(map[string]struct{}, len(j.Interfaces))
    for _, i := range j.Interfaces {
        ifs[i] = struct{}{}
    }
    if len(ifs) == 0 {
        p.AnyInterface = true
    }
    p.Interfaces = ifs

    switch strings.ToLower(j.Mode) {
    case "passthrough":
        if len(j.Addresses) != 0 {
            return fmt.Errorf("Specifying addresses is not allowed in passthrough mode")
        }
        p.Mode = ModePassthrough
    case "rotate":
        if len(j.Addresses) == 0 {
            return fmt.Errorf("Must specify addresses in rotate mode")
        }
        p.Mode = ModeRotate
        for _, addr := range j.Addresses {
            if addr.IP.To4() != nil {
                p.AddressesV4 = append(p.AddressesV4, addr)
            } else {
                p.AddressesV6 = append(p.AddressesV6, addr)
            }
        }
    }

    protocols := 0
    for _, p := range j.Protocols {
        switch strings.ToLower(p) {
        case "tcp4":
            protocols |= ProtocolTCP4
        case "tcp6":
            protocols |= ProtocolTCP6
        case "tcp":
            protocols |= ProtocolTCP
        case "udp4":
            protocols |= ProtocolUDP4
        case "udp6":
            protocols |= ProtocolUDP6
        case "udp":
            protocols |= ProtocolUDP
        case "ipv4":
            protocols |= ProtocolIPv4
        case "ipv6":
            protocols |= ProtocolIPv6
        case "any":
            protocols |= ProtocolAny
        default:
            return fmt.Errorf("Unknown protocol '%s'", p)
        }
    }
    if protocols == 0 {
        return fmt.Errorf("Must specify at least one protocol")
    }
    p.Protocols = protocols

    return nil
}

func parseIP(s string) net.IP {
    ip := net.ParseIP(s)
    if ip == nil {
        return nil
    }
    if ip4 := ip.To4(); ip4 != nil {
        ip = ip4
    }
    return ip
}

func (i *IP) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    ip := parseIP(s)
    if ip == nil {
        return fmt.Errorf("Invalid ip '%s'", s)
    }
    *i = (IP)(ip)
    return nil
}

func (b *IPBlock) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    _, block, err := net.ParseCIDR(s)
    if err != nil {
        ip := parseIP(s)
        if ip == nil {
            return err
        }
        size := len(ip) * 8
        block = &net.IPNet {
            IP:   ip,
            Mask: net.CIDRMask(size, size),
        }
    }
    *b = *(*IPBlock)(block)
    return nil
}

