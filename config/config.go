package config

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "math/rand"
    "net"
    "os"
    "time"
)

const (
    ProtocolTCP4 int = 0x01
    ProtocolTCP6     = 0x02
    ProtocolUDP4     = 0x04
    ProtocolUDP6     = 0x08

    ProtocolTCP      = ProtocolTCP4 | ProtocolTCP6
    ProtocolUDP      = ProtocolUDP4 | ProtocolUDP6

    ProtocolIPv4     = ProtocolTCP4 | ProtocolUDP4
    ProtocolIPv6     = ProtocolTCP6 | ProtocolUDP6

    ProtocolAny      = ProtocolTCP  | ProtocolUDP
)

const (
    ModeRotate      int = iota
    ModePassthrough
)

const (
    ViaAddress int = iota
    ViaTun
)

type Config struct {
    AllowUnknown bool
    DefaultRoutes bool
    ExtraRoutes []Route
    Policy []Policy
}

type Route struct {
    Destination IPBlock
    Source net.IP
    Via int
}

type routeJson struct {
    Destination IPBlock
    Source IP
    Via string
}

type Policy struct {
    Protocols int
    AnyInterface bool
    Interfaces map[string]struct{}
    Mode int
    AddressesV4 []IPBlock
    AddressesV6 []IPBlock
}

type policyJson struct {
    Protocols []string
    Interfaces []string
    Mode string
    Addresses []IPBlock
}

type IP net.IP
type IPBlock net.IPNet

func init() {
    rand.Seed(time.Now().UnixNano())
}

func From(src string) (*Config, error) {
    file, err := os.Open(src)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    data, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }

    cfg := &Config {
        AllowUnknown: false,
        DefaultRoutes: true,
    }

    if err := json.Unmarshal(data, cfg); err != nil {
        return nil, err
    }

    return cfg, nil
}

func (c *Config) Apply(iface string, proto int) (bool, net.IP) {
    v6 := (proto & ProtocolIPv6) != 0
    for _, p := range c.Policy {
        if (p.Protocols & proto) == 0 {
            continue
        }
        if !p.AnyInterface {
            if _, match := p.Interfaces[iface]; !match {
                continue
            }
        }
        switch p.Mode {
        case ModePassthrough:
            return true, nil
        case ModeRotate:
            var blocks []IPBlock
            var bytes int
            if v6 {
                blocks = p.AddressesV6
                bytes = 16
            } else {
                blocks = p.AddressesV4
                bytes = 4
            }

            if len(blocks) == 0 {
                continue
            }

            block := blocks[rand.Intn(len(blocks))]
            ip := append([]byte(nil), block.IP...)

            bits := make([]byte, bytes)
            rand.Read(bits)

            for i, v := range bits {
                ip[i] = ip[i] | (v &^ block.Mask[i])
            }

            return true, ip
        default:
            panic(fmt.Sprintf("Unhandled mode %d", p.Mode))
        }
    }
    return c.AllowUnknown, nil
}

