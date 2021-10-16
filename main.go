package main

import (
    "flag"
    "fmt"
    "os"
    "os/signal"
    "runtime"
    "syscall"

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
    netNsPath = flag.String("netns", "", "path to network namespace (/run/netns/{name} or /proc/{pid}/ns/net)")
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

func checkErr(err error, msg string, args ...interface{}) {
    if err != nil {
        fmt.Fprintf(os.Stderr, msg, args)
        fmt.Fprintf(os.Stderr, ": %v", err)
        os.Exit(1)
    }
}

func main() {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT)
    signal.Notify(sigCh, syscall.SIGTERM)

    flag.Parse()

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
