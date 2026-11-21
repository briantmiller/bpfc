# A layer 2-4 firewall with Cisco IOS access lists

bpfc reads Cisco IOS access lists. Put the lists you already know in a file
named `<priority>.acl` under `/etc/bpfc/interfaces.d/<interface>/ingress` (or
`egress`), and bpfcd compiles and applies them. `bpfcctl show access-lists`
shows them with their matches as IOS does, entries with `log` write
`%SEC-6-IPACCESSLOGP` lines, and reflexive lists give you stateful replies.

This guide assumes you know IOS access lists. It says what works, how it
maps onto bpfc, and where bpfc differs from a router.

The examples are in `dist/examples/acl` (installed to
`/usr/share/doc/bpfc/examples/acl`); the test suite loads each of them.

Contents:

1. [A first list](#1-a-first-list)
2. [Where the files go](#2-where-the-files-go)
3. [What you can write](#3-what-you-can-write)
4. [How a list is applied](#4-how-a-list-is-applied)
5. [Matches, top and clearing counters](#5-matches-top-and-clearing-counters)
6. [Logging](#6-logging)
7. [Reflexive lists: replies to what went out](#7-reflexive-lists-replies-to-what-went-out)
8. [IPv6 and MAC lists](#8-ipv6-and-mac-lists)
9. [When a list is wrong](#9-when-a-list-is-wrong)
10. [Differences from IOS](#10-differences-from-ios)
11. [Size and speed](#11-size-and-speed)
12. [Writing your own frontend](#12-writing-your-own-frontend)

## 1. A first list

`/etc/bpfc/interfaces.d/eth0/ingress/10.acl`:

```
ip access-list extended EDGE-IN
 10 deny ip 10.0.0.0 0.255.255.255 any log
 20 permit tcp any 203.0.113.0 0.0.0.255 established
 30 permit tcp any host 203.0.113.25 eq smtp
 40 permit udp any host 203.0.113.53 eq domain
 50 permit icmp any any echo-reply
 60 deny ip any any log
```

```
# systemctl reload bpfcd
# bpfcctl status
INTERFACE  DIR      PRIO  STATUS     ...  FILE
eth0       ingress  10    installed  ...  /etc/bpfc/interfaces.d/eth0/ingress/10.acl
# bpfcctl show access-lists
Extended IP access list EDGE-IN
    10 deny ip 10.0.0.0 0.255.255.255 any log (12 matches)
    20 permit tcp any 203.0.113.0 0.0.0.255 established (88213 matches)
    30 permit tcp any host 203.0.113.25 eq smtp (341 matches)
    40 permit udp any host 203.0.113.53 eq domain (2002 matches)
    50 permit icmp any any echo-reply
    60 deny ip any any log (97 matches)
```

A list defined in the file applies to the interface and direction of the
directory it is in. No `interface` or `ip access-group` line is needed (but
both are accepted, see below).

## 2. Where the files go

```
/etc/bpfc/interfaces.d/<interface>/ingress/<priority>.acl   inbound on that interface
/etc/bpfc/interfaces.d/<interface>/egress/<priority>.acl    outbound
/etc/bpfc/interfaces.d/%all%/ingress/<priority>.acl         every interface
/etc/bpfc/interfaces.d/%<kind>%/ingress/<priority>.acl      every interface of a kind (%veth%)
/etc/bpfc/interfaces.d/<interface>/xdp.acl                  in XDP, before TC ingress
/etc/bpfc/acl.d/*.acl                                       definitions shared by all of them
```

One file per interface and direction keeps programmatic changes small: a
tool rewrites `eth3/ingress/20.acl` and nothing else, and bpfcd reinstalls
only that program.

Shared lists and object groups go in `/etc/bpfc/acl.d/`. Every `.acl` file
can use what is defined there, and the interface's file only names the list:

```
! /etc/bpfc/acl.d/objects.acl
object-group network WEB-SERVERS
 host 192.0.2.10
 198.51.100.0 255.255.255.128
object-group service WEB
 tcp eq www
 tcp eq 443
ip access-list extended SERVERS-IN
 10 permit object-group WEB any object-group WEB-SERVERS
 20 deny ip any object-group WEB-SERVERS log
 30 permit ip any any
```

```
! /etc/bpfc/interfaces.d/eth1/ingress/20.acl
interface eth1
 ip access-group SERVERS-IN in
```

A change to a file in `acl.d` reinstalls every program that uses it on the
next `systemctl reload bpfcd`. Files in `acl.d` are read in name order, and a
list may be continued in a later file, as on IOS.

The same list on many interfaces: `%all%/ingress/20.acl` with
`ip access-group SERVERS-IN`. Each interface gets its own program and its own
counters.

## 3. What you can write

Lines start with optional spaces; `!` starts a comment, as in a
configuration; `remark` lines are kept out of the program.

**Lists**

| You write | |
|---|---|
| `ip access-list standard NAME` | source address only |
| `ip access-list extended NAME` | |
| `access-list 1-99, 1300-1999 ...` | numbered standard |
| `access-list 100-199, 2000-2699 ...` | numbered extended |
| `ipv6 access-list NAME` | |
| `mac access-list extended NAME` | non-IP frames |
| `object-group network NAME` | `host A`, `A MASK`, `A/len` (IPv4 and IPv6), `group-object`, `description` |
| `object-group service NAME` | `tcp`/`udp`/`tcp-udp [source op p] [op p]`, `icmp [type]`, a protocol, `group-object` |
| `ip reflexive-list timeout S` | default 300 |

**Entries** (`[seq] permit|deny ...`; without a number an entry gets the last
one plus 10; IPv6 lists also take `sequence N` at the end)

```
permit|deny <protocol> <source> [<op> <port>] <destination> [<op> <port>] [options]
```

- protocol: `ip` (`ipv6`), `tcp`, `udp`, `icmp`, `igmp`, `gre`, `esp`,
  `ahp`, `ospf`, `eigrp`, `pim`, `pcp`, `ipinip`, `nos`, `sctp` (IPv6), a
  number 0-255, or `object-group SERVICE`
- addresses: `any`, `host A`, `A WILDCARD` (non-contiguous wildcards work:
  `10.0.0.1 0.0.255.0`), `object-group NETWORK`; IPv6: `any`, `host A`,
  `A/len`, `object-group`
- ports (tcp, udp, sctp): `eq p [p ...]` (up to 10), `neq`, `lt`, `gt`,
  `range lo hi`; numbers or the IOS names (`www`, `domain`, `smtp`, `ntp`,
  `snmp`, `bootps`, ...)
- ICMP: a type and optional code (`3 4`) or a name (`echo`, `echo-reply`,
  `unreachable`, `packet-too-big`, `time-exceeded`, `port-unreachable`, ...;
  IPv6: `echo-request`, `nd-ns`, `nd-na`, `router-advertisement`, ...), right
  after the destination
- `established` (tcp: ACK or RST set)
- TCP flags `ack fin psh rst syn urg`: all the ones listed must be set
- `fragments`: non-initial fragments only (no ports or ICMP type with it)
- `dscp v` (0-63 or `ef`, `af41`, `cs6`, `default`), `precedence v`,
  `tos v`, `ttl eq|neq|lt|gt n`, `ttl range lo hi` (IPv4)
- `log`, `log-input`
- `reflect NAME [timeout S]` (permit entries), and as an entry,
  `evaluate NAME`

**Applying** (in an interface's file; optional when the file defines one list
per family):

```
interface eth1                        optional; if given it must be this interface
 ip access-group NAME [in|out]
 ipv6 traffic-filter NAME [in|out]
 mac access-group NAME [in]
```

`in`/`out` may be left out; if given it must match the directory
(`ingress` is `in`, `egress` is `out`).

**Options for bpfcd**: `! bpfc option on-failure keep|remove` (see
[section 9](#9-when-a-list-is-wrong)).

## 4. How a list is applied

A file becomes one bpfc program at its priority. For each packet:

1. IPv4 packets go through the IPv4 list (if the file applies one), IPv6
   packets through the IPv6 list, other frames through the MAC list. A packet
   of a family with no list passes untouched.
2. The transport header is read once (through up to four IPv6 extension
   headers): protocol, ports, TCP flags, ICMP type and code, fragment offset.
3. The entries are tried in sequence order; the first that matches decides.
   A list ends in an implicit `deny ip any any`.
4. The entry's counter goes up, a log line is queued if it logs, then:
   **permit** passes the packet on to the next program (a higher priority
   number, then the kernel); **deny** drops it.

Because a permit continues, programs at several priorities stack: a packet
reaches the kernel only if every list on the way permits it. Use this to keep
a common baseline (`%all%/ingress/10.acl`) and per-interface lists
(`eth1/ingress/20.acl`) apart.

**Fragments** follow the IOS rule. A later fragment has no transport header,
so:

- an entry with no port, flag or ICMP conditions matches it normally;
- a **permit** entry with transport conditions matches it on its addresses and
  protocol alone (otherwise no fragmented UDP would ever arrive);
- a **deny** entry with transport conditions does not match it;
- `fragments` entries match only later fragments.

## 5. Matches, top and clearing counters

Every entry counts packets and bytes, per interface. `show access-lists`
sums them over the interfaces a list is applied on:

```
bpfcctl show access-lists                 all lists
bpfcctl show access-lists SERVERS-IN      one
bpfcctl show access-lists SERVERS-IN interface eth1
bpfcctl show access-lists -l              with bytes
bpfcctl show ip access-lists              the same
bpfcctl clear access-list counters [NAME]
```

Entries with no matches show none, as on IOS. The implicit deny is shown
(`(implicit) deny ip any any (N matches)`) when something hit it.

`bpfcctl top` shows where the traffic is going right now:

```
# bpfcctl top 5
      PPS       BPS      MATCHES  INTERFACE    DIR  LIST             SEQ      ENTRY
    48.2k    412.5M     91822631  eth1         in   SERVERS-IN       10       permit object-group WEB any object-group WEB-SERVERS
     1.1k      2.0M      2003422  eth0         in   EDGE-IN          20       permit tcp any 203.0.113.0 0.0.0.255 established
       97     58.1k        88910  eth0         in   EDGE-IN          60       deny ip any any log
```

(`top N SECONDS`: the N busiest over SECONDS, default 20 over 1 second.)

The counters are the maps `BPFC_ACL_P` (packets) and `BPFC_ACL_B` (bytes) in
the map directory; each entry's key is in `/run/bpfc/meta/`, so scripts can
read them with `bpfc -r BPFC_ACL_P` too. They survive a reload of the list,
and an entry keeps its counter as long as its list name and sequence number
stay the same.

## 6. Logging

An entry with `log` or `log-input` logs the first packet of each flow (the
addresses, protocol and ports), and that flow again at most every 5 minutes.
bpfcd writes the lines IOS would, to the journal and to `/run/bpfc/acl.log`:

```
%SEC-6-IPACCESSLOGP: list EDGE-IN denied tcp 10.1.2.3(51514) -> 203.0.113.9(23), 1 packet
%SEC-6-IPACCESSLOGP: list WEB denied udp 10.9.0.7(53) (eth0 0011.2233.4455) -> 10.0.0.9(9999), 1 packet
%SEC-6-IPACCESSLOGDP: list EDGE-IN denied icmp 198.51.100.7 -> 203.0.113.1 (8/0), 1 packet
%SEC-6-IPACCESSLOGNP: list EDGE-IN denied gre 198.51.100.7 -> 203.0.113.1, 1 packet
%SEC-6-IPACCESSLOGS: list MGMT denied 10.8.2.1, 1 packet
%IPV6_ACL-6-ACCESSLOGP: list EDGE6-IN denied tcp 2001:db8:9::1(4000) -> 2001:db8:100::1(22), 1 packet
%SEC-6-MACACCESSLOG: list PORT-L2 denied 0011.2233.4455 -> ffff.ffff.ffff, type 0x88cc, on eth2, 1 packet
```

`log-input` adds the input interface and source MAC, as IOS does. Read them
with `journalctl -u bpfcd`, `bpfcctl log`, or follow them with
`bpfcctl log -f`. `acl.log` starts over at 16 MiB (the previous one is
`acl.log.1`).

Unlike IOS, bpfc does not send a 5-minute summary with a packet count; the
count is in `show access-lists`.

## 7. Reflexive lists: replies to what went out

```
! interfaces.d/eth0/egress/10.acl
ip reflexive-list timeout 300
ip access-list extended OUTBOUND
 10 permit tcp any any reflect MIRROR
 20 permit udp any any reflect MIRROR timeout 30
 30 permit icmp any any reflect MIRROR timeout 10
 40 permit ip any any

! interfaces.d/eth0/ingress/10.acl
ip access-list extended INBOUND
 10 evaluate MIRROR
 20 permit tcp any host 203.0.113.25 eq smtp
 30 deny ip any any log
```

A packet that matches a `reflect` entry records its flow (addresses,
protocol, ports, ICMP id) in the reflexive list. `evaluate` matches packets of
a recorded flow in either direction, so the replies come back in, and
refreshes the entry. An entry ends after its timeout without traffic, or
5 seconds after a FIN or RST.

The reflexive list lives in the map `RFX_<name>` (up to 65536 flows,
least recently used dropped first), shared by every program on the host: the
`reflect` may be on one interface's egress and the `evaluate` on another's
ingress, as on IOS.

## 8. IPv6 and MAC lists

IPv6 lists work like extended IPv4 lists. As on IOS, every IPv6 list ends in

```
 permit icmp any any nd-na
 permit icmp any any nd-ns
 deny ipv6 any any
```

so neighbour discovery keeps working; put an explicit deny for them before
the end if you mean it. Ports and ICMP types are found behind up to four
extension headers (hop-by-hop, routing, fragment, destination options). In a
packet with more, bpfc stops at the fifth: its protocol is that header's, so
only `ipv6` entries (and the implicit deny) can match it.

A MAC list matches frames that are neither IPv4 nor IPv6 (ARP, LLDP, STP and
the like): `any`, `host 0011.2233.4455`, `0011.2233.0000 0000.0000.ffff`, an
EtherType with a mask (`0x0806 0x0`), `vlan N`, `log`. It applies inbound
only. To filter both, put a MAC list and an IP list in the same file:

```
mac access-list extended PORT-L2
 permit any any 0x0806 0x0
 deny any any log
ip access-list extended PORT-IP
 permit ip 10.50.0.0 0.0.0.255 any
mac access-group PORT-L2 in
ip access-group PORT-IP in
```

## 9. When a list is wrong

A list with an error is not installed: `bpfcctl status` marks it, and
`bpfcctl show eth0 ingress 10` gives the file, line and reason:

```
/etc/bpfc/interfaces.d/eth0/ingress/10.acl:7: 'time-range' is not supported (bpfc refuses what it cannot apply exactly; see doc/firewall.md)
```

bpfc refuses everything it cannot apply exactly. It never skips an option it
does not understand, since a firewall that quietly ignores half an entry is
worse than one that refuses it.

When a new version of a list fails, the old one keeps running (status
`failed-kept`), so a typo does not open the firewall. To have a failed list
removed instead (traffic then passes unfiltered):

```
! bpfc option on-failure remove
```

or `on_failure = remove` in `bpfc.conf` for every program. When the broken
file cannot be read far enough to say, the option of the version that is
running counts.

`bpfcctl show eth0 ingress 10 --source` prints the bpfc program a list
became.

## 10. Differences from IOS

- **Direction comes from the directory.** `ip access-group X out` in an
  ingress file is an error.
- **One list per family per file.** Use more priorities to stack lists.
- **permit continues to the next program**, it does not accept the packet for
  good; deny drops.
- **Logging** is per flow with no summaries (section 6).
- **Counters are per interface** and summed by `show access-lists`.
- **Not supported** (an error names them): `time-range`, `dynamic`,
  `option`, `match-all`/`match-any`, `flow-label`, `routing`, `hbh`,
  `dest-option`, `mobility`, `auth`, `undetermined-transport`,
  `packet-length`, `ttl` in IPv6 lists, `cos` and `lsap` in MAC lists,
  `range` in network object groups, `ip access-list logging`/`resequence`.
- Network object groups need contiguous masks (they become a prefix table);
  wildcards in entries may be non-contiguous.
- TCP flag keywords require all the flags listed to be set.

## 11. Size and speed

The transport header is read once per packet; each entry then costs a few
comparisons. An entry with ports costs about 25 eBPF instructions, plus as
many again for the later-fragment rule of permit entries, and one per `eq`
port and service-group member (each becomes its own comparison). Counting
and logging run once per packet, whatever the list length. A program may
have 32768 instructions, about 600 typical entries; bpfc says so when a list
is too long (split it over two priorities).

Object groups of networks are prefix tables: a group of 3000 prefixes costs
the same as one of 3.

## 12. Writing your own frontend

`acl` is one frontend: a program that turns a file type into bpfc. bpfcd and
bpfc treat any `<priority>.<type>` file the same way, and look for the
program `<type>` in `/etc/bpfc/frontends`, then `/usr/libexec/bpfc/frontends`.
A frontend may be a shell or Python script or a binary. It gets the file as
its argument and the interface, hook and priority in `BPFC_*` variables, and
prints bpfc, each instruction ending in `;`. See FRONTENDS in `bpfc(8)` for
the full contract. A minimal one:

```sh
#!/bin/sh
# /etc/bpfc/frontends/blocklist: 20.blocklist files, one address per line
echo "name blocklist on $BPFC_IFNAME;"
echo "prefix-map BLOCK_$BPFC_IFINDEX 4096 static;"
grep -v '^#' "$BPFC_FILE" | while read a; do [ -n "$a" ] && echo "prefix BLOCK_$BPFC_IFINDEX $a;"; done
echo "match ip-src in BLOCK_$BPFC_IFINDEX; drop; end-match;"
```
