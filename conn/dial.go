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

func chooseBindAddress(dst net.IP) net.IP {
    if router != nil {
         iface, gw, preferred, err := router.Route(dst)
         if err != nil {
             log.Warningf("Unable to route address %v: %v", dst, err)
             return nil
         }
         log.Debugf("Remote addr %s: iface %s, gw %s, addr %s", dst.String(), iface.Name, gw.String(), preferred.String())
         log.Debugf("Using local address %s", preferred.String())
         return preferred
    }
    return nil
}

func DialTCP(ctx context.Context, address net.IP, port uint16) (net.Conn, error) {
    var localAddr net.Addr
    if ip := chooseBindAddress(address); ip != nil {
        localAddr = &net.TCPAddr { ip, 0, "" }
    }
    d := &net.Dialer {
        LocalAddr: localAddr,
    }
    return d.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.FormatUint(uint64(port), 10)))
}

