package netlinkfd

import (
    "os"
    "syscall"
    "unsafe"

    "golang.org/x/sys/unix"

    "github.com/mdlayher/netlink"
)

// code based on https://github.com/mdlayher/netlink/blob/3afd4859c706377609869778464492e1f78f34b4/conn_linux.go

type sock struct {
    fd int
}

func NewFromFD(fd int) (*Conn, error) {
    if err := unix.Bind(fd, &unix.SockaddrNetlink {
        Family: unix.AF_NETLINK,
        Groups: 0,
    }); err != nil {
        return nil, err
    }

    return &Conn {
        Conn: netlink.NewConn(&sock { fd: fd }, 0), 
    }, nil
}

func (s *sock) Close() error {
    return unix.Close(s.fd)
}

func (s *sock) Send(m netlink.Message) error {
    b, err := m.MarshalBinary()
    if err != nil {
        return err
    }
    sa := &unix.SockaddrNetlink { Family: unix.AF_NETLINK }
    return unix.Sendmsg(s.fd, b, nil, sa, 0)
}

func (s *sock) SendMessages(messages []netlink.Message) error {
    var buf []byte
    for _, m := range messages {
        b, err := m.MarshalBinary()
        if err != nil {
            return err
        }
        buf = append(buf, b...)
    }

    sa := &unix.SockaddrNetlink { Family: unix.AF_NETLINK }
    return unix.Sendmsg(s.fd, buf, nil, sa, 0)
}

func (s *sock) Receive() ([]netlink.Message, error) {
    b := make([]byte, os.Getpagesize())
    for {
        n, _, _, _, err := unix.Recvmsg(s.fd, b, nil, unix.MSG_PEEK)
        if err != nil {
            return nil, err
        }

        if n < len(b) {
            break
        }

        b = make([]byte, len(b) * 2)
    }

    n, _, _, _, err := unix.Recvmsg(s.fd, b, nil, 0)
    if err != nil {
        return nil, err
    }

    raw, err := syscall.ParseNetlinkMessage(b[:align(n)])
    if err != nil {
        return nil, err
    }

    msgs := make([]netlink.Message, 0, len(raw))
    for _, r := range raw {
        msgs = append(msgs, netlink.Message {
            Header: sysToHeader(r.Header),
            Data:   r.Data,
        })
    }

    return msgs, nil
}

const nlmsgAlignTo = 4

// #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
func align(len int) int {
	return ((len) + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1)
}

func sysToHeader(r syscall.NlMsghdr) netlink.Header {
	// NB: the memory layout of Header and syscall.NlMsgHdr must be
	// exactly the same for this unsafe cast to work
	return *(*netlink.Header)(unsafe.Pointer(&r))
}
