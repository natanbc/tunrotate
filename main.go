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
    "syscall"

    "golang.org/x/sys/unix"

    specs "github.com/opencontainers/runtime-spec/specs-go"
    "gvisor.dev/gvisor/runsc/specutils"

    "gvisor.dev/gvisor/pkg/log"
    "gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
    "gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
    "gvisor.dev/gvisor/pkg/tcpip/link/tun"

    "github.com/natanbc/tunrotate/stack"
)

var (
    debug     = flag.Bool("debug", false, "enable debug logging")
    netNsPath = flag.String("netns", "", "path to network namespace (/run/netns/{name} or /proc/{pid}/ns/net). Needs root privileges")
    tunDevice = flag.String("tun-device", "tun0", "tun device to use")
    targetPid = flag.Int("pid", 0, "pid of a process in the wanted network namespace. Does not need root privileges")
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

func getTunDevice() (int, uint32) {
    if *targetPid != 0 {
        log.Infof("Using tunopen on pid %d", *targetPid)

        path := "/tmp/tun.sock"
        syscall.Unlink(path)
        addr, err := net.ResolveUnixAddr("unix", path)
        checkErr(err, "[!] Unable to resolve unix socket address")
        ul, err := net.ListenUnix("unix", addr)
        checkErr(err, "[!] Unable to listen on unix socket")
        checkErr(os.Chmod(path, 0700), "[!] Unable to chmod unix socket")

        cmd := exec.Command("./tunopen/tunopen", fmt.Sprintf("%d", *targetPid), *tunDevice, path)
        cmd.Stdin = nil
        cmd.Stdout = nil
        cmd.Stderr = os.Stderr
        checkErr(cmd.Start(), "[!] Unable to start tunopen helper process")
        go func() {
            checkErr(cmd.Wait(), "[!] tunopen error")
        }()

        uc, err := ul.AcceptUnix()
        checkErr(err, "[!] Unable to accept unix connection")

        msg, oob := make([]byte, 4), make([]byte, 128)
        _, oobn, _, _, err := uc.ReadMsgUnix(msg, oob)
        checkErr(err, "[!] Unable to read message from unix socket")

        cmsgs, err := syscall.ParseSocketControlMessage(oob[0:oobn])
        checkErr(err, "[!] Unable to parse socket control message")

        fds, err := syscall.ParseUnixRights(&cmsgs[0])
        checkErr(err, "[!] Unable to parse unix rights")

        uc.Close()
        ul.Close()
        syscall.Unlink(path)

        fd := fds[0]
        mtu := binary.LittleEndian.Uint32(msg)
        checkErr(unix.SetNonblock(fd, true), "[!] Unable to set tun device in non blocking mode")

        return fd, mtu
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

    if *netNsPath != "" {
        log.Infof("Restoring root netns")
        restore()
    }

    return fd, mtu
}

func checkErr(err error, msg string, args ...interface{}) {
    if err != nil {
        fmt.Fprintf(os.Stderr, msg, args)
        fmt.Fprintf(os.Stderr, ": %v", err)
        os.Exit(1)
    }
}

func main() {
    runtime.GOMAXPROCS(1)
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT)
    signal.Notify(sigCh, syscall.SIGTERM)

    flag.Parse()

    fd, mtu := getTunDevice()

    ep, err := fdbased.New(&fdbased.Options {
        MTU: mtu,
        FDs: []int{fd},
        RXChecksumOffload: true,
    })
    checkErr(err, "[!] Unable to create endpoint")

    _, err = stack.New(ep)
    checkErr(err, "[!] Unable to create stack")

    log.Infof("Started!")
    <-sigCh
}
