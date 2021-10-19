package conn

import (
    "context"
    "fmt"
    "net"
    "strconv"
    "time"

    "github.com/google/gopacket/routing"

    "gvisor.dev/gvisor/pkg/log"

    "github.com/natanbc/tunrotate/config"
)

var router routing.Router
var cfg *config.Config

func SetConfig(c *config.Config) {
    cfg = c
}

func init() {
    go func() {
        for {
            r, err := routing.New()
            if err != nil {
                log.Warningf("Unable to read routing table: %v", err)
            } else {
                router = r
            }
            time.Sleep(60 * time.Second)
        }
    }()
}

func allowUnknown() bool {
    return cfg == nil || cfg.AllowUnknown
}

func chooseBindAddress(dst net.IP, network string) (bool, net.IP) {
    if router != nil {
         iface, gw, preferred, err := router.Route(dst)
         if err != nil {
             log.Warningf("Unable to route address %s/%v: %v", network, dst, err)
             return allowUnknown(), nil
         }
         log.Debugf("Remote addr %s: iface %s, gw %s, addr %s", dst.String(), iface.Name, gw.String(), preferred.String())
         if cfg == nil {
             log.Debugf("Using local address %s/%s", network, preferred)
             return true, preferred
         }

         v6 := dst.To4() == nil
         var proto int
         if network == "tcp" {
            if v6 {
                proto = config.ProtocolTCP6
            } else {
                proto = config.ProtocolTCP4
            }
         } else {
             if v6 {
                 proto = config.ProtocolUDP6
             } else {
                 proto = config.ProtocolUDP4
             }
         }
         allow, ip := cfg.Apply(iface.Name, proto)
         if allow {
             if ip == nil {
                 ip = preferred
             }
             log.Debugf("Using local address %s/%s", network, ip)
         } else {
             log.Debugf("Blocking connection")
         }
         return allow, ip
    }
    return allowUnknown(), nil
}

func dial(network string, timeout time.Duration, ip net.IP, port uint16) (net.Conn, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    return doDial(ctx, network, ip, port)
}

func doDial(ctx context.Context, network string, address net.IP, port uint16) (net.Conn, error) {
    var localAddr net.Addr
    allow, ip := chooseBindAddress(address, network)
    if !allow {
        return nil, fmt.Errorf("Connection blocked")
    }
    if ip != nil {
        if network == "tcp" {
            localAddr = &net.TCPAddr { ip, 0, "" }
        } else if network == "udp" {
            localAddr = &net.UDPAddr { ip, 0, "" }
        }
    }
    d := &net.Dialer {
        LocalAddr: localAddr,
    }
    return d.DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)))
}

