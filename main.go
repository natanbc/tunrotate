package main

import (
    "flag"
    "fmt"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "syscall"
    "time"
    "unsafe"

    "golang.org/x/sys/unix"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/link/fdbased"

    "github.com/jsimonetti/rtnetlink"

    "github.com/natanbc/tunrotate/config"
    "github.com/natanbc/tunrotate/conn"
    "github.com/natanbc/tunrotate/netlinkfd"
    "github.com/natanbc/tunrotate/stack"
)

var (
    logLevel   = flag.String("loglevel", "info", "Log level [debug|info|warn]")
    netNsPath  = flag.String("netns", "", "path to network namespace (/run/netns/{name} or /proc/{pid}/ns/net). Needs root privileges")
    targetPid  = flag.Int("pid", 0, "pid of a process in the wanted network namespace. Does not need root privileges")
    tunDevice  = flag.String("tun-device", "tun0", "tun device to use")
    configPath = flag.String("config-path", "", "configuration file to use")
    tunMtu     = flag.Uint("mtu", 65520, "mtu to set for the device")
    tunQueues  = flag.Uint("queues", 8, "number of tun queues")
    fileLimit  = flag.Uint64("file-limit", 0, "soft open file descriptor to set, sets soft limit to hard limit if 0, min(file-limit, hard-limit) otherwise")
    sameUser   = flag.Bool("same-user", false, "Whether or not the spawned task should see its UID as the same of the caller (even if false it still maps to the same UID)")
)
var cfg *config.Config

func init() {
    flag.DurationVar(&conn.TcpConnectTimeout, "tcp-connect-timeout", 60 * time.Second, "How long to wait for a TCP connection before failing")
    flag.DurationVar(&conn.TcpWaitTimeout, "tcp-wait-timeout", 60 * time.Second, "How long to wait for data before giving up")
    flag.DurationVar(&conn.UdpConnectTimeout, "udp-connect-timeout", 20 * time.Second, "How long to wait for an UDP connection before failing")
    flag.DurationVar(&conn.UdpWaitTimeout, "udp-wait-timeout", 20 * time.Second, "How long to wait for data before giving up")
}

func setFlagsFromConfig() {
    if cfg == nil {
        return
    }

    wasFlagPassed := func(name string) bool {
        found := false
        flag.Visit(func(f *flag.Flag) {
            if f.Name == name {
                found = true
            }
        })
        return found
    }

    maybeSet := func(v *time.Duration, name string, configValue config.Duration) {
        if wasFlagPassed(name) {
            return
        }
        if configValue > config.Duration(0) {
            *v = time.Duration(configValue)
        }
    }

    maybeSet(&conn.TcpConnectTimeout, "tcp-connect-timeout", cfg.TcpConnectTimeout)
    maybeSet(&conn.TcpWaitTimeout, "tcp-wait-timeout", cfg.TcpWaitTimeout)
    maybeSet(&conn.UdpConnectTimeout, "udp-connect-timeout", cfg.UdpConnectTimeout)
    maybeSet(&conn.UdpWaitTimeout, "udp-wait-timeout", cfg.UdpWaitTimeout)
}

func setOpenFileLimit() {
    var rLimit syscall.Rlimit
    err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Warningf("Unable to get current rlimit")
        return
    }
    rLimit.Cur = rLimit.Max
    if *fileLimit != 0 && *fileLimit < rLimit.Cur {
        rLimit.Cur = *fileLimit
    }
    err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Warningf("Unable to set rlimit")
        return
    }
    err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        log.Warningf("Unable to get updated rlimit")
        return
    }
    log.Infof("Set open file limit to %d", rLimit.Cur)
}

func setNetNS(fd uintptr) error {
    if _, _, err := syscall.RawSyscall(unix.SYS_SETNS, fd, syscall.CLONE_NEWNET, 0); err != 0 {
        return err
    }
    return nil
}

func enterNetNS(path string) (func(), error) {
    newNS, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer newNS.Close()

    oldNS, err := os.Open("/proc/self/ns/net")
    if err != nil {
        return nil, err
    }

    runtime.LockOSThread()
    if err := setNetNS(newNS.Fd()); err != nil {
        runtime.UnlockOSThread()
        return nil, fmt.Errorf("Unable to enter network namespace: %v", err)
    }

    return func() {
        defer runtime.UnlockOSThread()
        defer oldNS.Close()
        if err := setNetNS(oldNS.Fd()); err != nil {
            panic(fmt.Sprintf("Unable to restore network namespace: %v", err))
        }
    }, nil
}

func tunhelper(args ...string) (*exec.Cmd, error) {
    if lp, err := exec.LookPath("tunhelper"); err == nil {
        return exec.Command(lp, args...), nil
    }
    self, err := os.Executable()
    if err != nil {
        return nil, fmt.Errorf("Unable to find tunhelper executable: os.Executable() failed")
    }
    dir := filepath.Dir(self)
    if info, err := os.Stat(filepath.Join(dir, "tunhelper")); err == nil && !info.IsDir() {
        return exec.Command(filepath.Join(dir, "tunhelper"), args...), nil
    }
    if info, err := os.Stat(filepath.Join(dir, "tunhelper/tunhelper")); err == nil && !info.IsDir() {
        return exec.Command(filepath.Join(dir, "tunhelper/tunhelper"), args...), nil
    }
    return nil, fmt.Errorf("Unable to find tunhelper executable: no tunhelper or tunhelper/tunhelper executable next to %s", self)
}

//returns (tun, netlink)
func getTunDevice() ([]int, int) {
    if *tunQueues == 0 || *tunQueues > 252 {
        fmt.Fprintf(os.Stderr, "[!] Number of queues should be in the range [1, 252]\n")
        os.Exit(1)
    }

    if *targetPid != 0 {
        log.Infof("Using tunhelper on pid %d", *targetPid)

        sockFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0);
        checkErr(err, "[!] Unable to create socket pair")

        parentSocket := os.NewFile(uintptr(sockFds[0]), "sockerpair/parent")
        childSocket  := os.NewFile(uintptr(sockFds[1]), "sockerpair/child")

        cmd, err := tunhelper("tun", fmt.Sprintf("%d", *targetPid), *tunDevice, "3", fmt.Sprintf("%d", *tunQueues))
        checkErr(err, "[!] Unable to start tunhelper process")
        cmd.Stdin = nil
        cmd.Stdout = nil
        cmd.Stderr = os.Stderr
        cmd.ExtraFiles = []*os.File { childSocket }
        checkErr(cmd.Start(), "[!] Unable to start tunhelper process")

        wg := sync.WaitGroup {}
        wg.Add(1)

        //separate goroutine so tunhelper errors get caught and the process exits
        go func() {
            checkErr(cmd.Wait(), "[!] tunhelper error")
            wg.Done()
        }()

        fc, err := net.FileConn(parentSocket)
        checkErr(err, "[!] Unable to create FileConn")
        uc := fc.(*net.UnixConn)

        msg, oob := make([]byte, 4), make([]byte, unix.CmsgSpace(int((*tunQueues + 1) * 4)))
        _, oobn, _, _, err := uc.ReadMsgUnix(msg, oob)
        checkErr(err, "[!] Unable to read message from unix socket")

        cmsgs, err := syscall.ParseSocketControlMessage(oob[0:oobn])
        checkErr(err, "[!] Unable to parse socket control message")

        fds, err := syscall.ParseUnixRights(&cmsgs[0])
        checkErr(err, "[!] Unable to parse unix rights")

        uc.Close()

        tunFds := fds[0:*tunQueues]
        netlinkFd := fds[*tunQueues]
        for _, fd := range tunFds {
            checkErr(unix.SetNonblock(fd, true), "[!] Unable to set tun device in non blocking mode")
        }

        //wait for tunhelper to finish
        wg.Wait()


        return tunFds, netlinkFd
    }

    var restore func()
    if *netNsPath != "" {
        var err error
        log.Infof("Joining netns %s", *netNsPath)
        restore, err = enterNetNS(*netNsPath)
        checkErr(err, "[!] Failed to join netns %s", *netNsPath)
    }

    fds := make([]int, *tunQueues)

    var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
    copy(ifr.name[:], *tunDevice)
    ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE

    for i, _ := range fds {
        fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
        checkErr(err, "[!] Unable to create tun device")
        _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
        if errno != 0 {
            checkErr(errno, "[!] Unable to set IFF")
        }
        checkErr(unix.SetNonblock(fd, true), "[!] Unable to set nonblocking mode")
        fds[i] = fd
    }

    netlinkFd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE)
    checkErr(err, "[!] Unable to open netlink socket")

    if *netNsPath != "" {
        log.Infof("Restoring root netns")
        restore()
    }

    return fds, netlinkFd
}

func configureNetwork(c *netlinkfd.Conn) error {
    idx, err := c.GetInterfaceIndex(*tunDevice)
    if err != nil {
        return err
    }

    if err := c.NewAddress(&rtnetlink.AddressMessage {
        Family:       uint8(unix.AF_INET),
        PrefixLength: 24,
        Scope:        unix.RT_SCOPE_UNIVERSE,
        Index:        idx,
        Attributes:   &rtnetlink.AddressAttributes {
            Address:   net.ParseIP("10.0.0.2"),
            Local:     net.ParseIP("10.0.0.2"),
            Broadcast: net.ParseIP("10.0.0.255"),
        },
    }); err != nil {
        return err
    }

    if err := c.NewAddress(&rtnetlink.AddressMessage {
        Family:       uint8(unix.AF_INET6),
        PrefixLength: 64,
        Scope:        unix.RT_SCOPE_UNIVERSE,
        Index:        idx,
        Attributes:   &rtnetlink.AddressAttributes {
            Address:   net.ParseIP("fc00:0:0:6969::2"),
            Local:     net.ParseIP("fc00:0:0:6969::2"),
        },
    }); err != nil {
        return err
    }

    link, err := c.GetLink(idx)
    if err != nil {
        return err
    }

    if err := c.SetLink(&rtnetlink.LinkMessage {
        Family:     link.Family,
        Type:       link.Type,
        Index:      idx,
        Flags:      unix.IFF_UP,
        Change:     unix.IFF_UP,
        Attributes: &rtnetlink.LinkAttributes {
            MTU: uint32(*tunMtu),
        },
    }); err != nil {
        return err
    }

    routes := make([]config.Route, 0)
    if cfg == nil || cfg.DefaultRoutes {
        allV4 := config.IPBlock {
            IP:   net.ParseIP("0.0.0.0").To4(),
            Mask: net.CIDRMask(0, 32),
        }
        allV6 := config.IPBlock {
            IP:   net.ParseIP("::"),
            Mask: net.CIDRMask(0, 128),
        }
        routes = append(
            routes,
            config.Route { Destination: allV4, Via: config.ViaTun },
            config.Route { Destination: allV6, Via: config.ViaTun },
        )
    }
    if cfg != nil {
        routes = append(routes, cfg.ExtraRoutes...)
    }

    toNetlink := func(r config.Route) *rtnetlink.RouteMessage {
        var family int
        if r.Destination.IP.To4() == nil {
            family = unix.AF_INET6
        } else {
            family = unix.AF_INET
        }

        msg := &rtnetlink.RouteMessage {
            Family:     uint8(family),
            Table:      uint8(unix.RT_TABLE_MAIN),
            Protocol:   uint8(unix.RTPROT_BOOT),
            Scope:      uint8(unix.RT_SCOPE_UNIVERSE),
            Type:       uint8(unix.RTN_UNICAST),
        }

        switch r.Via {
        case config.ViaTun:
            msg.Attributes = rtnetlink.RouteAttributes {
                OutIface: idx,
            }
        case config.ViaAddress:
            msg.Attributes = rtnetlink.RouteAttributes {
                Gateway: r.Source,
            }
        default:
            panic("Unhandled via")
        }

        dstLength, _ := r.Destination.Mask.Size()
        if dstLength != 0 {
            msg.Attributes.Dst = r.Destination.IP
            msg.DstLength = uint8(dstLength)
        }

        return msg
    }

    for _, r := range routes {
        if err := c.AddRoute(toNetlink(r)); err != nil {
            return err
        }
    }

    return nil
}

func checkErr(err error, msg string, args ...interface{}) {
    if err != nil {
        fmt.Fprintf(os.Stderr, msg, args)
        fmt.Fprintf(os.Stderr, ": %v\n", err)
        os.Exit(1)
    }
}

func main() {
    cmdDoneCh := make(chan struct{}, 1)
    setupDone := make(chan struct{}, 1)
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT)
    signal.Notify(sigCh, syscall.SIGTERM)

    flag.Parse()

    switch strings.ToLower(*logLevel) {
    case "warn":  log.SetLevel(log.Warning)
    case "info":  log.SetLevel(log.Info)
    case "debug": log.SetLevel(log.Debug)
    default:
        fmt.Fprintf(os.Stderr, "[!] Invalid log level: %s", *logLevel)
        os.Exit(1)
    }

    setOpenFileLimit()

    if *configPath != "" {
        log.Infof("Loading configuration from %s", *configPath)
        c, err := config.From(*configPath)
        checkErr(err, "[!] Unable to parse config")
        cfg = c
        conn.SetConfig(c)
    }

    setFlagsFromConfig()

    if len(flag.Args()) > 0 {
        unshareReadPipe, unshareWritePipe, err := os.Pipe()
        checkErr(err, "[!] Failed to create unshare pipe")
        waitReadPipe, waitWritePipe, err := os.Pipe()
        checkErr(err, "[!] Failed to create wait pipe")

        //create process in new user and network namespace
        var args []string
        args = append(args, "unshare", fmt.Sprintf("%t", *sameUser), "3", "4")
        args = append(args, flag.Args()...)
        cmd, err := tunhelper(args...)
        checkErr(err, "[!] Unable to start target process")
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        cmd.ExtraFiles = []*os.File { unshareWritePipe, waitReadPipe }
        checkErr(cmd.Start(), "[!] Unable to start target process")

        _, err = unshareReadPipe.Read(make([]byte, 16))
        checkErr(err, "[!] Unable to read from unshare pipe")

        go func() {
            <-setupDone
            waitWritePipe.Write([]byte{0})
            waitWritePipe.Close()

            cmd.Wait()

            if cmd.ProcessState.ExitCode() != 0 {
                os.Exit(cmd.ProcessState.ExitCode())
            }
            cmdDoneCh<- struct{}{}
        }()
        *targetPid = cmd.Process.Pid
    }

    tunFds, netlinkFd := getTunDevice()
    log.Infof("Using %d queues", len(tunFds))

    netlink, err := netlinkfd.NewFromFD(netlinkFd)
    checkErr(err, "[!] Unable to connect to netlink")
    checkErr(configureNetwork(netlink), "[!] Unable to configure device addresses")
    netlink.Close()

    ep, err := fdbased.New(&fdbased.Options {
        FDs: tunFds,
        MTU: uint32(*tunMtu),
        RXChecksumOffload: true,
    })
    checkErr(err, "[!] Unable to create endpoint")

    _, err = stack.New(ep)
    checkErr(err, "[!] Unable to create stack")

    log.Infof("Started!")

    setupDone <- struct{}{}

    select {
    case <-sigCh:
        break;
    case <-cmdDoneCh:
        break;
    }
}
