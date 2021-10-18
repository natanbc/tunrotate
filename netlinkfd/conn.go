package netlinkfd

import (
    "fmt"

    "golang.org/x/sys/unix"

    "github.com/jsimonetti/rtnetlink"

    "github.com/mdlayher/netlink"
)

type Conn struct {
    Conn *netlink.Conn
}

func (c *Conn) Close() error {
    return c.Conn.Close()
}

func (c *Conn) Execute(m rtnetlink.Message, family uint16, flags netlink.HeaderFlags) ([]rtnetlink.Message, error) {
    b, err := m.MarshalBinary()
    if err != nil {
        return nil, err
    }

    rawMsgs, err := c.Conn.Execute(netlink.Message {
        Header: netlink.Header {
            Type:  netlink.HeaderType(family),
            Flags: flags,
        },
        Data: b,
    })
    if err != nil {
        return nil, err
    }

    msgs := make([]rtnetlink.Message, 0, len(rawMsgs))
    for _, nm := range rawMsgs {
        var m rtnetlink.Message
        switch nm.Header.Type {
        case unix.RTM_GETLINK, unix.RTM_NEWLINK, unix.RTM_DELLINK:
            m = &rtnetlink.LinkMessage {}
        case unix.RTM_GETADDR, unix.RTM_NEWADDR, unix.RTM_DELADDR:
            m = &rtnetlink.AddressMessage {}
        case unix.RTM_GETROUTE, unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
            m = &rtnetlink.RouteMessage {}
        case unix.RTM_GETNEIGH, unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
            m = &rtnetlink.NeighMessage {}
        default:
            continue
        }
        if err := m.UnmarshalBinary(nm.Data); err != nil {
            return nil, err
        }
        msgs = append(msgs, m)
    }

    return msgs, nil
}

func (c *Conn) GetInterfaceIndex(name string) (uint32, error) {
    msgs, err := c.Execute(&rtnetlink.LinkMessage {}, unix.RTM_GETLINK, netlink.Request | netlink.Dump)
    if err != nil {
        return 0, err
    }

    for _, m := range msgs {
        lm := m.(*rtnetlink.LinkMessage)
        if lm.Attributes.Name == name {
            return lm.Index, nil
        }
    }
    return 0, fmt.Errorf("Unable to find interface %s", name)
}

func (c *Conn) NewAddress(msg *rtnetlink.AddressMessage) error {
    flags := netlink.Request | netlink.Create | netlink.Acknowledge | netlink.Excl
    _, err := c.Execute(msg, unix.RTM_NEWADDR, flags)
    return err
}

func (c *Conn) GetLink(idx uint32) (*rtnetlink.LinkMessage, error) {
    flags := netlink.Request | netlink.DumpFiltered
    links, err := c.Execute(&rtnetlink.LinkMessage { Index: idx }, unix.RTM_GETLINK, flags)

    if err != nil {
        return nil, err
    }
    if len(links) != 1 {
        return nil, fmt.Errorf("too many/little matches, expected 1, actual %d", len(links))
    }

    return links[0].(*rtnetlink.LinkMessage), nil
}

func (c *Conn) SetLink(msg *rtnetlink.LinkMessage) error {
    _, err := c.Execute(msg, unix.RTM_NEWLINK, netlink.Request | netlink.Acknowledge)
    return err
}

func (c *Conn) AddRoute(msg *rtnetlink.RouteMessage) error {
    flags := netlink.Request | netlink.Create | netlink.Acknowledge | netlink.Excl
    _, err := c.Execute(msg, unix.RTM_NEWROUTE, flags)
    return err
}

