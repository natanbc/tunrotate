package conn

import (
    "context"
    "net"
    "strconv"
    "time"

    "github.com/google/gopacket/routing"

    "gvisor.dev/gvisor/pkg/log"
)

var router routing.Router

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

func chooseBindAddress(dst net.IP, network string) net.IP {
    if router != nil {
         iface, gw, preferred, err := router.Route(dst)
         if err != nil {
             log.Warningf("Unable to route address %s/%v: %v", network, dst, err)
             return nil
         }
         log.Debugf("Remote addr %s: iface %s, gw %s, addr %s", dst.String(), iface.Name, gw.String(), preferred.String())
         log.Debugf("Using local address %s/%s", network, preferred.String())
         return preferred
    }
    return nil
}

func dial(network string, timeout time.Duration, ip net.IP, port uint16) (net.Conn, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    return doDial(ctx, network, ip, port)
}

func doDial(ctx context.Context, network string, address net.IP, port uint16) (net.Conn, error) {
    var localAddr net.Addr
    if ip := chooseBindAddress(address, network); ip != nil {
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

