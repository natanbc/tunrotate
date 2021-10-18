package main

import (
    "encoding/binary"
    "flag"
    "fmt"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "runtime"
    "strings"
    "sync"
    "syscall"
    "time"

    "golang.org/x/sys/unix"

    specs "github.com/opencontainers/runtime-spec/specs-go"
    "gvisor.dev/gvisor/runsc/specutils"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
    "gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
    "gvisor.dev/gvisor/pkg/tcpip/link/tun"

    "github.com/jsimonetti/rtnetlink"

    "github.com/natanbc/tunrotate/netlinkfd"
    "github.com/natanbc/tunrotate/stack"
)

var (
    logLevel  = flag.String("loglevel", "info", "Log level [debug|info|warn]")
    netNsPath = flag.String("netns", "", "path to network namespace (/run/netns/{name} or /proc/{pid}/ns/net). Needs root privileges")
    targetPid = flag.Int("pid", 0, "pid of a process in the wanted network namespace. Does not need root privileges")
    tunDevice = flag.String("tun-device", "tun0", "tun device to use")
)

func enterNetNS(path string) (func(), error) {
    runtime.LockOSThread()
    restoreNS, err := specutils.ApplyNS(specs.LinuxNamespace {
        Type: specs.NetworkNamespace,
        Path: path,
    })
    if err != nil {
        runtime.UnlockOSThread()
        return nil, fmt.Errorf("unable to enter net namespace %q: %v", path, err)
    }
    return func() {
        restoreNS()
        runtime.UnlockOSThread()
    }, nil
}

//returns (tun, mtu, netlink)
func getTunDevice() (int, uint32, int) {
    if *targetPid != 0 {
        log.Infof("Using tunopen on pid %d", *targetPid)

        sockFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0);
        checkErr(err, "[!] Unable to create socket pair")

        parentSocket := os.NewFile(uintptr(sockFds[0]), "sockerpair/parent")
        childSocket  := os.NewFile(uintptr(sockFds[1]), "sockerpair/child")

        cmd := exec.Command("./tunhelper/tunhelper", "tun", fmt.Sprintf("%d", *targetPid), *tunDevice, "3")
        cmd.Stdin = nil
        cmd.Stdout = nil
        cmd.Stderr = os.Stderr
        cmd.ExtraFiles = []*os.File { childSocket }
        checkErr(cmd.Start(), "[!] Unable to start tunopen helper process")

        wg := sync.WaitGroup {}
        wg.Add(1)

        //separate goroutine so tunopen errors get caught and the process exits
        go func() {
            checkErr(cmd.Wait(), "[!] tunopen error")
            wg.Done()
        }()

        fc, err := net.FileConn(parentSocket)
        checkErr(err, "[!] Unable to create FileConn")
        uc := fc.(*net.UnixConn)

        msg, oob := make([]byte, 4), make([]byte, 128)
        _, oobn, _, _, err := uc.ReadMsgUnix(msg, oob)
        checkErr(err, "[!] Unable to read message from unix socket")

        cmsgs, err := syscall.ParseSocketControlMessage(oob[0:oobn])
        checkErr(err, "[!] Unable to parse socket control message")

        fds, err := syscall.ParseUnixRights(&cmsgs[0])
        checkErr(err, "[!] Unable to parse unix rights")

        uc.Close()

        fd := fds[0]
        netlinkFd := fds[1]
        mtu := binary.LittleEndian.Uint32(msg)
        checkErr(unix.SetNonblock(fd, true), "[!] Unable to set tun device in non blocking mode")

        //wait for tunopen to finish
        wg.Wait()


        return fd, mtu, netlinkFd
    }

    var restore func()
    if *netNsPath != "" {
        var err error
        log.Infof("Joining netns %s", *netNsPath)
        restore, err = enterNetNS(*netNsPath)
        checkErr(err, "[!] Failed to join netns %s", *netNsPath)
    }

    fd, err := tun.Open(*tunDevice)
    checkErr(err, "[!] open(%s)", *tunDevice)

    mtu, err := rawfile.GetMTU(*tunDevice)
    checkErr(err, "[!] GetMTU(%s)", *tunDevice)
    log.Infof("MTU(%s) = %v", *tunDevice, mtu)

    netlinkFd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_ROUTE)
    checkErr(err, "[!] Unable to open netlink socket")

    if *netNsPath != "" {
        log.Infof("Restoring root netns")
        restore()
    }

    return fd, mtu, netlinkFd
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
        Family: link.Family,
        Type:   link.Type,
        Index:  idx,
        Flags:  unix.IFF_UP,
        Change: unix.IFF_UP,
    }); err != nil {
        return err
    }

    if err := c.AddRoute(&rtnetlink.RouteMessage {
        Family:     uint8(unix.AF_INET),
        Table:      uint8(unix.RT_TABLE_MAIN),
        Protocol:   uint8(unix.RTPROT_BOOT),
        Scope:      uint8(unix.RT_SCOPE_UNIVERSE),
        Type:       uint8(unix.RTN_UNICAST),
        Attributes: rtnetlink.RouteAttributes {
            Gateway: net.ParseIP("10.0.0.1"),
        },
    }); err != nil {
        return err
    }

    if err := c.AddRoute(&rtnetlink.RouteMessage {
        Family:     uint8(unix.AF_INET6),
        Table:      uint8(unix.RT_TABLE_MAIN),
        Protocol:   uint8(unix.RTPROT_BOOT),
        Scope:      uint8(unix.RT_SCOPE_UNIVERSE),
        Type:       uint8(unix.RTN_UNICAST),
        Attributes: rtnetlink.RouteAttributes {
            Gateway: net.ParseIP("fc00:0:0:6969::1"),
        },
    }); err != nil {
        return err
    }

    return nil
}

func checkErr(err error, msg string, args ...interface{}) {
    if err != nil {
        fmt.Fprintf(os.Stderr, msg, args)
        fmt.Fprintf(os.Stderr, ": %v", err)
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

    if len(flag.Args()) > 0 {
        unshareReadPipe, unshareWritePipe, err := os.Pipe()
        checkErr(err, "[!] Failed to create unshare pipe")
        waitReadPipe, waitWritePipe, err := os.Pipe()
        checkErr(err, "[!] Failed to create wait pipe")

        //create process in new user and network namespace
        var args []string
        args = append(args, "unshare", "3", "4")
        args = append(args, flag.Args()...)
        cmd := exec.Command("./tunhelper/tunhelper", args...)
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        cmd.ExtraFiles = []*os.File { unshareWritePipe, waitReadPipe }
        checkErr(cmd.Start(), "[!] Unable to start process")

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
        //give it time to enter the new namespaces
        time.Sleep(500 * time.Millisecond)
    }

    fd, mtu, netlinkFd := getTunDevice()

    netlink, err := netlinkfd.NewFromFD(netlinkFd)
    checkErr(err, "[!] Unable to connect to netlink")
    checkErr(configureNetwork(netlink), "[!] Unable to configure device addresses")
    netlink.Close()

    ep, err := fdbased.New(&fdbased.Options {
        MTU: mtu,
        FDs: []int{fd},
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
