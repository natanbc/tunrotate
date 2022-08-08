# tunrotate

An attempt at rotating IP addresses transparently inside a network namespace.

# Usage

## Privileged usage, configuring an existing network namespace

Run `tunrotate --netns path/to/network/ns` as root. If you created the namespace with `ip netns add <name>`,
the namespace path can be `/run/netns/<name>`, otherwise it can be `/proc/<pid of process in netns>/ns/net`.

## Unprivileged usage

Unprivileged usage needs the `tunhelper` program to be available, either in PATH, next to the `tunrotate` binary,
or in a `tunhelper` folder next to the tunrotate binary. It's a simple C program, available in `tunhelper/tunhelper.c`.

#### Configuring an existing network namespace

Run `tunrotate --pid <pid>`. The process must have be inside a namespace created with `unshare -Urn` or
similar as the same user running tunrotate.

#### Create namespace and spawn process in it

Run `tunrotate <command> [args]`.

# Configuration file

```json
{
    "AllowUnknown": bool,
    "DefaultRoutes": bool,
    "ExtraRoutes": [Route],
    "Policy": [Policy]
}
```

- AllowUnknown: whether connections to a destination not listed in the routing configuration (or default routes, if enabled) should be attempted. Defaults to `false`.
- DefaultRoutes: whether default routes for 0.0.0.0/0 and ::/0 should be set inside the namespace. Defaults to `true`.
- ExtraRoutes: additional routes to configure inside the namespace. Defaults to `[]`.
- Policy: policies to determine where to send packets from inside the namespace. Defaults to `[]`, which simply acts as if any connections made inside the namespace were made by the tunrotate process if AllowUnknown is true, otherwise always drops all connections.

### Route objects

```json
{
    "Destination": IPnet,
    "Via": string
}
```

- Destination: IP and optional netmask (defaulting to /32 or /128, if absent) to match.
- Via: Where to send the packets to. Should always be "tun".

### Policy objects

```json
{
    "Protocols": [string],
    "Interfaces: [string],
    "Mode": string,
    "Addresses": [IPnet]
}
```

- Protocols: which protocols should this rule match. Valid protocols are `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`, `ipv4`, `ipv6` and `any`.
- Interfaces: if present, match only traffic that would get sent through one of these interfaces by default. Defaults to `[]`.
- Mode: which mode to operate on. Must be either `passthrough`, which simply forwards traffic, or `rotate`, which binds to a random address in the given list of addresses for each connection.
- Addresses: IPs and optional netmasks (defaulting to /32 or /128, if absent) to bind connections on. Must be present if `Mode` is `rotate`, must not be present if `Mode` is `passthrough`.

## Example config

Assuming you have `2001:abc:def::/48` routed to the `he-ipv6` interface, and can connect to the internet by binding
to any address within that block, and have IPv4 access through the interface `eth0`, you can configure a namespace
where all IPv4 traffic is forwarded through `eth0` and IPv6 traffic gets assigned random addresses from `he-ipv6` with

```json
{
    "AllowUnknown": false,
    "Policy": [
        {
            "Protocols": [ "ipv4" ],
            "Interfaces": [ "eth0" ],
            "Mode": "passthrough"
        },
        {
            "Protocols": [ "ipv6" ],
            "Interfaces": [ "he-ipv6" ],
            "Mode": "rotate",
            "Addresses": [
                "2001:abc:def::/48"
            ]
        }
    ]
}
```

