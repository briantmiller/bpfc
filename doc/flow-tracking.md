# Flow tracking with bpfc

This guide is for network engineers who want bpfc programs that keep state
per flow, per host, per customer or per conversation: NAT tables, counters,
rate limits, load sharing, duplicate removal. It assumes you know IP, TCP and
UDP well and that you have written a few bpfc `match` lines. It does not
assume you know how hash tables work.

Every example here is a file in `dist/examples/flow` (installed to
`/usr/share/doc/bpfc/examples/flow`). They are shown as they are, and the
test suite runs each of them on real packets.

Contents:

1. [Tables and keys](#1-tables-and-keys)
2. [A first table: bytes per source](#2-a-first-table-bytes-per-source)
3. [Building a key: pack, hash or flow-key](#3-building-a-key-pack-hash-or-flow-key)
4. [Direction: plain, reverse and symmetric](#4-direction-plain-reverse-and-symmetric)
5. [The fields](#5-the-fields)
6. [Reading and writing tables from the shell](#6-reading-and-writing-tables-from-the-shell)
7. [Commands built on keys](#7-commands-built-on-keys)
8. [Examples](#8-examples)
9. [Things to know](#9-things-to-know)
10. [Quick reference](#10-quick-reference)

## 1. Tables and keys

A bpfc map is a table that survives from one packet to the next. Each row has
a **key** (which row) and a **value** (what is stored there), both 64-bit
numbers:

| key | value |
|---|---|
| 10.0.0.1 | 88213004 |
| 10.0.0.2 | 1209933 |

Most of the work is deciding what the key is: "per source address", "per
VLAN and address", "per TCP connection", "per conversation, both directions
together". That decision is what this guide is about. Once you have a key,
`count`, `get map`, `set map`, `calc-map` and the commands in section 7 do
the rest.

A key has to fit in 64 bits. Two IPv4 addresses (32 + 32 bits) fit exactly.
A full 5-tuple (32 + 32 + 8 + 16 + 16 = 104 bits) does not, and neither does
one IPv6 address (128 bits). That is why there are two ways to build a key:

* **pack** puts the fields side by side. Exact and readable, but at most 64
  bits.
* **hash** turns any number of fields into a fixed-size number. It takes any
  key, but it cannot be read back.

## 2. A first table: bytes per source

```
match ip;
  count PKTS BYTES ip-src;
end-match;
```

Attach it and send some traffic:

```
bpfc -i eth0 -d ingress -p 10 'match ip; count PKTS BYTES ip-src; end-match'
```

Then read the table back with `-K` naming the key's fields:

```
$ bpfc -r BYTES -K ip-src
# ip-src value
10.0.0.1 88213004
10.0.0.7 1209933
```

`count` adds 1 to the packet count of the key and the frame's length to the
byte count, atomically, so it is exact even when many CPUs receive traffic at
once. The key here is one field, the source address, so it is stored as it
is and `-K ip-src` turns it back into an address.

## 3. Building a key: pack, hash or flow-key

### Which one do I use?

| You want | Use | Why |
|---|---|---|
| A key you can read back (`bpfc -r -K`), or decode in the program (`unpack`) | `pack` | exact; the fields are still there |
| Fields that fit in 64 bits (two IPv4 addresses, an address and a port, VLAN + address) | `pack` | no collisions at all |
| More than 64 bits: a 5-tuple, IPv6 addresses | `hash` | fixed size; collisions are rare (see below) |
| A number from 0 to N-1 to pick a link, a backend or a sample | `hash ... buckets N` | spreads evenly |
| The usual IPv4 5-tuple key | `get flow-key` | shorthand for `hash` of the 5-tuple |

`count`, `seen` and `over-rate` decide for you: they pack the fields when
they fit in 64 bits and hash them otherwise.

### pack

```
pack K ip-src ip-dst;              # K = source address << 32 | destination address
pack K vlan-id ip-src;             # 12 + 32 bits
pack K ip-src/24 dst-port;         # the source's /24 and the port: 24 + 16 bits
pack K ip-proto:8 ip-src dst-port; # 8 + 32 + 16 = 56 bits
```

The first field goes in the highest bits. Each field takes its natural width
(the table in section 5): an address 32 bits, a port 16, a VLAN id 12, a MAC
48. Two ways to make a field smaller:

* `ip-src/24` keeps the network part, 24 bits. Every host of the /24 gets the
  same key, which is what you want for "per subnet".
* `field:<bits>` keeps the low bits, for example `ip-src:8` for the last
  octet, or `%VAR:16` for a variable that holds a 16-bit number.

If the fields add up to more than 64 bits, bpfc stops with an error and
suggests `hash`. Packed keys are what make `bpfc -r MAP -K 'vlan-id ip-src'`
print readable tables, and `unpack` takes a packed value apart again:

```
pack ME ip-src src-port;           # 48 bits: who we are
unpack %ME ADDR:32 PORT:16;        # and back
```

### hash

```
hash K 64 ip-src ip-dst ip-proto src-port dst-port;     # a TCP/UDP flow
hash K 64 ip6-src ip6-dst ip6-proto src-port dst-port;  # the same for IPv6
hash K 32 ip-src ip-dst;                                 # 32 bits are enough for a small table
hash B buckets 4 ip-src ip-dst;                          # B = 0, 1, 2 or 3
```

`hash` takes any fields, including IPv6 addresses, and gives a number of the
size you ask for (1 to 64 bits). The same fields always give the same number,
on every CPU, every kernel and every architecture, and `bpfc -H` computes it
from the shell (section 6).

The price is that a hash cannot be turned back into the fields, and two
different flows can, very rarely, get the same number: a **collision**. How
rare depends on the size you ask for and how many entries the table holds:

| hash size | entries in the table | chance that any two of them collide |
|---|---|---|
| 64 bits | 1 000 000 | about 1 in 37 million |
| 64 bits | 16 000 000 | about 1 in 140 000 |
| 32 bits | 1 000 | about 1 in 8 600 |
| 32 bits | 100 000 | about 70 % (expect one) |

So use 64 bits for map keys. When the fields fit in 64 bits, a 64-bit hash
does not collide (the mixing is one-to-one), but then `pack` is the
better choice anyway because it stays readable.

`buckets N` turns the hash into 0 to N-1, spread evenly over the N values,
for choosing one of N links, firewalls, backends or for sampling one flow in
N. (Taking the hash modulo N spreads unevenly when N does not divide 2^64.)

`seed <n|%VAR>` gives a different, unrelated hash of the same fields. Use it
to try a second choice when the first is taken (the NAT example in section
8.1 does this) or to make the hash unpredictable from outside (section 9).

A key whose fields are not in the packet is 0: `hash K 64 ip-src ip-dst` on
an ARP or IPv6 packet stores 0, so 0 always means "not this kind of packet".
A 64-bit hash of a packet that has the fields is never 0.

### flow-key

```
get flow-key K;              # the same as hash K 64 ip-src ip-dst ip-proto src-port dst-port
get flow-key K reverse;      # ... reverse ...
get flow-key K symmetric;    # ... symmetric ...
```

`flow-key` is the usual IPv4 5-tuple, written short. It gives exactly the
same number as the `hash` line, so you can mix the two forms, and compute
either with `bpfc -H 'hash 64 ip-src=... ip-dst=... ip-proto=6 src-port=...
dst-port=...'`.

(The value of `flow-key` changed when `hash` was added: maps keyed by it
start new entries after an upgrade, so flowmon's counters start again from
0. The keys are now the same as `hash` gives, and ports are 0 for fragments,
as below.)

### The long way, and why the new commands are better

Before `pack` and `hash`, a key was built by hand from `get`, `calc lsh` and
`calc or`. The README's NAT example (README, Advanced Examples 4) builds its
TCP key like this:

```
decl FLOW_KEY 8;
decl TCP_SRC 4;
get ip-dst FLOW_KEY;
calc bswap FLOW_KEY;
get ip-src IP_SRC;
get tcp-src TCP_SRC;
calc lsh TCP_SRC 16;
get tcp-dst TCP_DST;
calc or FLOW_KEY %TCP_SRC;
calc or FLOW_KEY %TCP_DST;
```

It works, but it is hard to read, and it hides a flaw: after the byte swap
the address sits in the same low 32 bits as the two ports, so `calc or`
mixes them, and different flows can get the same key. With `pack` the same
key is one line, each field in its own bits:

```
pack K reverse ip-src src-port dst-port;     # remote address, remote port, our port: 64 bits, exact
```

## 4. Direction: plain, reverse and symmetric

A conversation between A (10.0.0.1, port 51515) and B (192.0.2.10, port 443)
has packets in two directions. Field names always mean what is in the packet
header: `ip-src` is the source address of *this* packet, whatever the
interface or hook. So the two directions read different values:

| | ip-src | ip-dst | src-port | dst-port |
|---|---|---|---|---|
| A to B | 10.0.0.1 | 192.0.2.10 | 51515 | 443 |
| B to A | 192.0.2.10 | 10.0.0.1 | 443 | 51515 |

Three ways to build a key from them:

| | A to B packet gives | B to A packet gives | Use it for |
|---|---|---|---|
| plain | key(A, B) | key(B, A) | one entry per direction |
| `reverse` | key(B, A) | key(A, B) | finding the other direction's entry |
| `symmetric` | key(A, B) | key(A, B) | one entry per conversation |

**Plain** keys the packet as it is. Use it when the two directions are
different things to you: upload and download counters, or a TCP sender's
state.

**reverse** swaps every source/destination pair before building the key,
which gives the key the *reply* will have. Use it to write an entry that the
other direction will look up. A NAT stores the inside address under the key
the reply will carry:

```
# going out (egress): store under the reply's key
pack K reverse ip-src src-port dst-port;     # reads ip-dst, dst-port, src-port of this packet
# coming back (ingress): look up with the reply's own fields
pack K ip-src src-port dst-port;
```

**symmetric** gives both directions the same key, so a conversation has one
entry. Use it to count conversations, or to send both directions of a flow
to the same firewall.

### How symmetric decides

`symmetric` puts each pair in a fixed order: the lower value first. It
compares the first pair in your list (usually the addresses) as numbers, so
10.0.0.1 comes before 192.0.2.10. Only when they are equal (a host talking to
itself) does it look at the next pair (the ports). One decision is taken for
all pairs, so an address and its port always stay together:

```
hash K 64 symmetric ip-src ip-dst ip-proto src-port dst-port;
# 10.0.0.1:51515 -> 192.0.2.10:443   keyed as (10.0.0.1, 192.0.2.10, 6, 51515, 443)
# 192.0.2.10:443 -> 10.0.0.1:51515   keyed as (10.0.0.1, 192.0.2.10, 6, 51515, 443)
```

(If the addresses and the ports were each put in order on their own, the two
different flows A:1000 to B:80 and A:80 to B:1000 would get the same key.)

The pairs are `ip-src`/`ip-dst`, `src-port`/`dst-port` (and `tcp-src`/
`tcp-dst`, `udp-src`/`udp-dst`), `src-mac`/`dst-mac` and `ip6-src`/
`ip6-dst`. Fields without a partner (the protocol, the VLAN, a variable)
stay where they are. With `symmetric`, each pair field needs its partner in
the list, with the same width and prefix, or bpfc stops with an error.

### Not the hook, and not who started

None of the three looks at whether the program runs on ingress or egress.
That would be wrong: a router sees a forwarded packet on the ingress of one
interface and the egress of another, and its reply the other way round, so
the hook says nothing about which end is the client.

`symmetric` does not tell you who started the conversation either: the lower
address is not necessarily the client. When that matters, record it the
first time you see the flow, for example store the first packet's
`pack ip-src ip-dst` as the value, or keep two counters per conversation and
pick by comparing `ip-src` with the stored first source.

Rule of thumb: plain for one entry per direction, `reverse` to find the
other direction, `symmetric` for one entry per conversation.

## 5. The fields

| field | bits | what it is | 0 when |
|---|---|---|---|
| `ip-src`, `ip-dst` | 32 | IPv4 addresses | |
| `ip-src/<len>`, `ip-dst/<len>` | len | the network part (`/24`: 24 bits) | |
| `ip-proto` | 8 | IPv4 protocol (6 TCP, 17 UDP, 1 ICMP, ...) | |
| `ip-tos` | 8 | the whole TOS byte | |
| `dscp` | 6 | DSCP (names: `ef`, `af41`, `cs6`, ... below) | |
| `ecn` | 2 | ECN (`not-ect`, `ect1`, `ect0`, `ce`) | |
| `ip-ttl` | 8 | time to live | |
| `ip-ident` | 16 | IPv4 identification | |
| `ip-len` | 16 | IPv4 total length | |
| `src-port`, `dst-port` | 16 | TCP, UDP or SCTP port | other protocols; every fragment |
| `tcp-src`, `tcp-dst` | 16 | TCP port only | not TCP; every fragment |
| `udp-src`, `udp-dst` | 16 | UDP port only | not UDP; every fragment |
| `icmp-type`, `icmp-code` | 8 | ICMP (ICMPv6 in an IPv6 key) | not ICMP |
| `icmp-id` | 16 | identifier of an echo request or reply | not an echo |
| `ip6-src`, `ip6-dst` | 128 | IPv6 addresses (`hash` only) | |
| `ip6-src/<len>`, `ip6-dst/<len>` | 128 | the network part, the rest zeroed | |
| `ip6-proto` | 8 | IPv6 next header | |
| `ip6-flow` | 20 | IPv6 flow label | |
| `ip6-tclass` | 8 | IPv6 traffic class | |
| `src-mac`, `dst-mac` | 48 | Ethernet addresses | |
| `eth-proto` | 16 | EtherType | |
| `vlan-id` | 12 | the VLAN id | untagged |
| `%VAR` | its size | a variable (`decl V 2`: 16 bits) | |
| `<number>:<bits>` | bits | a constant, e.g. `6:8` (`hash` needs no width: 32 bits) | |
| `bytes <offset\|%VAR> <1-8>` | 8 per byte | raw packet bytes, as `get bytes` | outside the packet |
| any other `get` field | its size | e.g. `gre-key`, `skb-mark` | as `get` |

Add `:<bits>` to any field to keep only its low bits (`ip-src:8`).

**Families.** A key with IPv4 fields (`ip-*`, `dscp`, ...) is for IPv4
packets; a key with IPv6 fields is for IPv6 packets; mixing the two is an
error. The port and ICMP fields follow: IPv6 when the key has IPv6 fields,
IPv4 otherwise. For a packet of another family the key is **absent**:
`hash` and `pack` store 0, and `count`, `seen` and `over-rate` do nothing (it
is not counted, it is not "seen", it is not over the rate). A key of only
Ethernet fields (`src-mac`, `vlan-id`, ...) or variables works for every
packet.

**Ports and fragments.** Ports are 0 for every fragment, the first included,
because only the first fragment carries them. So all fragments of a datagram
get the same key, as the kernel does it. For IPv6, ports are read only when
TCP, UDP or SCTP follows the fixed header directly; behind extension headers
they are 0. IPv4 headers with options are handled.

**Raw-IP devices** (tun, wireguard, GRE: `$L3OFF` 0) have no Ethernet
header: the MAC, EtherType and VLAN fields are a compile error there, the
rest works.

**DSCP names** (RFC 2474, 2597, 3246, 5865, 8622): `default` or `be` or
`cs0` (0), `le` (1), `cs1`-`cs7` (8, 16, ... 56), `af11` (10), `af12` (12),
`af13` (14), `af21`-`af23` (18, 20, 22), `af31`-`af33` (26, 28, 30),
`af41`-`af43` (34, 36, 38), `va` (44), `ef` (46).

## 6. Reading and writing tables from the shell

### Reading: -r with -K and -V

`bpfc -r MAP` prints raw hex. With `-K '<fields>'` the keys are decoded as a
`pack` of those fields; with `-V '<fields>'` the values too. A header line
names the columns, and the values are decimal unless `-V` decodes them:

```
$ bpfc -r CUST_B -K 'vlan-id ip-src'
# vlan-id ip-src value
101 100.64.1.20 88213004
102 100.64.7.3 1209933
```

That is easy to sort and filter with `sort` and `awk`. Hashed keys cannot
be decoded; `-r` shows them as `0x...` numbers. `-R` (several maps joined on
their keys) takes `-K` too and prints the key's fields joined by commas:

```
$ bpfc -R CUST_P,CUST_B -K 'vlan-id ip-src'
# key CUST_P CUST_B
101,100.64.1.20 0x9a1 0x541f3cc
```

### Finding a hashed entry: -H

`bpfc -H` computes a key the way the program does, from the values you give.
Write the `hash` or `pack` command without the variable, with `=value` after
each field:

```
$ bpfc -H 'hash 64 ip-src=10.1.1.5 ip-dst=192.0.2.10 ip-proto=6 src-port=51515 dst-port=443'
0x79ed058c92d1c433
$ bpfc -r FLOW_B | grep 0x79ed058c92d1c433
```

Values: addresses as addresses, MACs as MACs, `dscp=ef`, `ecn=ce`, numbers
in decimal or `0x` hex. A prefix field takes a whole address (`ip-src/24=10.1.1.5`).
A variable needs its width: `%I:16=7`. A constant field is written as in the
program (`6:8`). Another `get` field needs its width: `gre-key:32=5`.
`symmetric` and `seed` work as in the program. With `reverse`, give the
packet's values for both fields of each pair, as they are in the packet.

### Writing and deleting: -w and -x

`-w MAP KEY VALUE` writes an entry; `-x MAP KEY` deletes one. The key (and
the value) can be a number or a `pack`/`hash` text as for `-H`:

```
bpfc -w CUST_P 'pack vlan-id=200 ip-src=192.0.2.1' 0
bpfc -x CUST_P 'pack vlan-id=200 ip-src=192.0.2.1'
bpfc -w FW_LINKS 0 $(cat /sys/class/net/fw0/ifindex)
```

For a prefix map the key is a prefix (next section).

## 7. Commands built on keys

These commands take a key the same way: a list of fields (packed when they
fit in 64 bits, hashed otherwise, `symmetric` or `reverse` first if you
want), or one `%VAR` that already holds a key.

### count

```
count <MAP> [<BYTES_MAP>] <key...>
count PKTS ip-src;                         # packets per source
count PKTS BYTES vlan-id ip-src;           # and bytes per VLAN and source
count CONV_P CONV_B symmetric ip-src ip-dst;
```

Adds 1 to the packet map and, with a second map, the frame's length (as
`get len`: the frame as the hook sees it, Ethernet header included, an
offloaded VLAN tag not) to the byte map. Atomic. Absent keys are not counted.

### seen

```
match seen <MAP> <key...> within <time> [refresh]; ... end-match;
```

True when the same key was seen less than `<time>` ago. Every packet records
itself:

* a new key, or one last seen longer ago than `<time>`: not seen (the
  block is skipped), and a new window starts now;
* a key seen within `<time>`: seen. The window keeps running from the first
  sighting, so a duplicate arriving 40 ms after the original with
  `within 50ms` is seen, and one after 60 ms is not;
* with `refresh`, every sighting starts the window again: an idle timeout
  ("seen within the last 2 s of activity").

The record is atomic: if two copies of a packet arrive on two CPUs at the
same moment, exactly one of them is "seen". Times: `ns`, `us`, `ms`, `s`,
`m` (a unit is required: `50ms`, `2s`).

### over-rate

```
match over-rate <MAP> <key...> <rate> [burst <size>]; ... end-match;
```

True for the packets above `<rate>` per key, like a policer's exceed action:
drop them, re-mark them, count them. `else` gives the conforming ones.

| rate | meaning | burst is |
|---|---|---|
| `100/s` or `100pps` | packets per second | packets (`burst 20`) |
| `500kbit`, `10mbit`, `1gbit` | bits per second (1000-based, as tc) | bytes: `20000`, `64k` (k = 1024, as tc) |

Without `burst`, the burst is 100 ms of the rate, at least one packet (or
1514 bytes). A bit rate charges each packet its frame length (as `count`
does).

It is a single-rate policer (GCRA, equivalent to a token bucket of the
burst size filled at the rate): an idle key can send a full burst at once,
then the rate. It needs no lock: a conforming packet takes its share
atomically, so CPUs sharing a key cannot both use the same allowance.

### prefix-map and in

```
prefix-map ALLOW [entries];
match ip-src in ALLOW; ... end-match;
if ip-dst in ROUTES CLASS; ... end-if;    # the matching entry's value into CLASS
match %ADDR in ALLOW; ... end-match;     # an address in a variable (as get ip-src gives it)
```

A prefix map holds IPv4 prefixes and finds the longest one that contains an
address, like a routing table or a prefix list. Fill it from the shell; no
recompile is needed to change it:

```
bpfc -w ALLOW 10.0.0.0/8 1
bpfc -w ALLOW 10.1.2.0/24 2
bpfc -x ALLOW 10.1.2.0/24
bpfc -r ALLOW
# prefix value
10.0.0.0/8 1
```

### host, net, port, src-port, dst-port

```
match host 10.0.0.1;     # IPv4 source or destination
match net 10.0.0.0/8;    # source or destination in the prefix
match port 53;           # TCP, UDP or SCTP, source or destination port (or a range: 1000-2000)
match src-port 53;  match dst-port 443;
```

They read like tcpdump's `host`, `net` and `port`. They are IPv4 matches;
the port matches skip later fragments (a first fragment still has its
ports). `match tcp-dst` and friends remain for one protocol.

### dscp and ecn

```
match dscp ef; ... end-match;
set dscp af41;           # the ECN bits stay
set ecn ce;              # the DSCP stays
get dscp D;  get ecn E;
```

IPv4. The IP checksum is updated.

### get and set for ports and other fields

```
get src-port P;          # TCP or UDP (or SCTP), 0 otherwise
set src-port 1234;       # TCP or UDP, with the checksum
set dst-port %P;
get ip-ttl T;  get icmp-id I;  get icmp-type Y;  get icmp-code C;
```

### unpack

```
unpack %VALUE ADDR:32 PORT:16;
```

The opposite of `pack`: the first variable gets the highest of the bits
listed. NAT tables use it to store an address and a port in one value.

## 8. Examples

Each example names the hook to attach it to. Constants at the top
(`const`) can be changed with `-s NAME=VALUE` without editing the file.

### 8.1 NAT, three ways

The README's NAT (Advanced Examples 4) shows how a NAT works in bpfc: going
out, remember the inside address under a key and replace it by the router's
address; coming back, look the key up and put the inside address back. Here
it is three times: as it is in the README, written with `pack`, and then
improved with port translation.

**Basic: the README's version.** Each key is built by hand. This is the
README's code as it is (the test suite runs it):

ICMP:

```bash
#Store ICMP "echo request" flow information into map and change source IP to address of eth0
bpfc -i eth0 -d egress -p 100 "\
match icmp; \
	match icmp-type 8; \
		decl FLOW_KEY 8; \
		get ip-src IP_SRC; \
		get ip-dst FLOW_KEY; \
		calc bswap FLOW_KEY; \
		get bytes 38 2 ICMP_IDENT; \
		calc or FLOW_KEY %ICMP_IDENT; \
		set map ICMP_NAT %FLOW_KEY %IP_SRC; \
		set ip-src 10.0.0.30"

#Change the IP destination of ICMP "echo reply" packets received on eth0 to NAT'ed address
bpfc -i eth0 -d ingress -p 100 "\
match icmp; \
	match icmp-type 0; \
		decl FLOW_KEY 8; \
		get bytes 38 2 ICMP_IDENT; \
		get ip-src FLOW_KEY; \
		calc bswap FLOW_KEY; \
		calc or FLOW_KEY %ICMP_IDENT; \
		get map ICMP_NAT %FLOW_KEY IP_DST; \
		set ip-dst %IP_DST"
```

TCP:

```bash
#Match new TCP flows and create entry for flow in map
bpfc -i eth0 -d egress -p 160 "\
match tcp; \
	match tcp-flags SYN; \
		decl FLOW_KEY 8; \
		decl TCP_SRC 4; \
		get ip-dst FLOW_KEY; \
		calc bswap FLOW_KEY; \
		get ip-src IP_SRC; \
		get tcp-src TCP_SRC; \
		calc lsh TCP_SRC 16; \
		get tcp-dst TCP_DST; \
		calc or FLOW_KEY %TCP_SRC; \
		calc or FLOW_KEY %TCP_DST; \
		set map TCP_NAT %FLOW_KEY %IP_SRC"
#Change source IP to IP address of eth0
bpfc -i eth0 -d egress -p 164 'match tcp; set ip-src 10.0.0.30'

#Change the IP destination of TCP packets received on eth0 to NAT'ed address
bpfc -i eth0 -d ingress -p 160 "\
match tcp; \
	decl FLOW_KEY 8; \
	decl TCP_DST 4; \
	get tcp-dst TCP_DST; \
	get ip-src FLOW_KEY; \
	calc bswap FLOW_KEY; \
	calc lsh TCP_DST 16; \
	get tcp-src TCP_SRC; \
	calc or FLOW_KEY %TCP_DST; \
	calc or FLOW_KEY %TCP_SRC; \
	get map TCP_NAT %FLOW_KEY IP_DST; \
	set ip-dst %IP_DST"
```

UDP:

```bash
#Store UDP flow information into map and change source IP to address of eth0
bpfc -i eth0 -d egress -p 117 "\
match udp; \
	decl FLOW_KEY 8; \
	get ip-dst FLOW_KEY; \
	get ip-src IP_SRC; \
	get udp-src UDP_SRC; \
	calc bswap FLOW_KEY; \
	calc or FLOW_KEY %UDP_SRC; \
	set map UDP_NAT %FLOW_KEY %IP_SRC; \
	set ip-src 10.0.0.30"

#Change the IP destination of UDP packets received on eth0 to NAT'ed address
bpfc -i eth0 -d ingress -p 117 "\
match udp; \
	decl FLOW_KEY 8; \
	get ip-src FLOW_KEY; \
	get udp-dst UDP_DST; \
	calc bswap FLOW_KEY; \
	calc or FLOW_KEY %UDP_DST; \
	get map UDP_NAT %FLOW_KEY IP_DST; \
	set ip-dst %IP_DST"
```

It works, but the keys are fragile: the ICMP key ORs the 16-bit identifier
into the same bits as the address, and the TCP and UDP keys OR the ports into
the address, so different flows can share a key. Nothing tells two inside
hosts apart either.

**With pack: the same NAT, exact keys.** One file for both hooks
(`$HOOK` picks the half), and each key is one line with each field in its own
bits. `reverse` on the way out builds the key the reply will have, so the
ingress half reads it straight from the reply:

`nat-pack.bpfc`:

```
# nat-pack.bpfc: the README's NAT (example 4) written with pack. It works the
# same way: going out, the inside address is remembered and replaced by
# $WAN_IP; coming back, the reply's destination is set back to it. The keys
# are exact now: remote address, remote port and our port side by side.
# Attach the same file to the WAN interface's egress and ingress:
#   bpfc -i wan -d egress  -p 100 -f nat-pack.bpfc
#   bpfc -i wan -d ingress -p 100 -f nat-pack.bpfc
# Limit: no port translation. Two inside hosts that use the same source port
# to the same server share a key, and the replies of both go to the one that
# sent last. nat-pat.bpfc translates ports.
const WAN_IP 10.0.0.30;

when $HOOK == egress;
  # Key = what the reply will carry: "reverse" reads the reply's view of this
  # packet (its source is our destination, and the other way round).
  match icmp; match icmp-type 8;
    pack K reverse ip-src icmp-id;               # = ip-dst icmp-id of this packet
    get ip-src IN; set map ICMP_NAT %K %IN; set ip-src $WAN_IP;
  end-match; end-match;
  match tcp;
    pack K reverse ip-src src-port dst-port;     # remote address, remote port, our port
    get ip-src IN; set map TCP_NAT %K %IN; set ip-src $WAN_IP;
  end-match;
  match udp;
    pack K reverse ip-src src-port dst-port;
    get ip-src IN; set map UDP_NAT %K %IN; set ip-src $WAN_IP;
  end-match;
otherwise;
  # Coming in: the same key, read straight from the reply.
  match icmp; match icmp-type 0;
    pack K ip-src icmp-id; get map ICMP_NAT %K IN; if IN ne 0; set ip-dst %IN; end-if;
  end-match; end-match;
  match tcp;
    pack K ip-src src-port dst-port; get map TCP_NAT %K IN; if IN ne 0; set ip-dst %IN; end-if;
  end-match;
  match udp;
    pack K ip-src src-port dst-port; get map UDP_NAT %K IN; if IN ne 0; set ip-dst %IN; end-if;
  end-match;
end-when;
```

Its limit is the NAT itself: with no port translation, two inside hosts that
pick the same source port to the same server have the same key, and the
second overwrites the first. The test suite shows it: with two hosts sending
from port 5555 to the same server at once, both replies go to the second
host.

**With port translation (PAT).** Every inside flow gets a public port of its
own, so the inside hosts can no longer collide. The public port comes from
the flow's hash (`buckets` spreads it over the 40000 ports), and if a flow to
the same remote address and port already has it, the next `seed` gives
another port, up to four tries. A public port only has to be unique per
remote end, so the same ports serve every server.

`nat-pat.bpfc`:

```
# nat-pat.bpfc: NAT with port translation (PAT, "overload"). Every inside
# flow gets a public port of its own, so inside hosts that pick the same
# source port no longer collide. A public port only has to be unique per
# remote address and port, so the 40000 ports are reused for every server.
# TCP and UDP; ICMP echo as in nat-pack.bpfc. Attach to the WAN interface:
#   bpfc -i wan -d egress  -p 100 -f nat-pat.bpfc
#   bpfc -i wan -d ingress -p 100 -f nat-pat.bpfc
#   bpfc -r PAT_IN       (one line per translated flow)
# Entries age out when the maps are full (LRU). Two new flows choosing the
# same port on two CPUs at the same instant could both take it (very rare).
const WAN_IP 10.0.0.30;
const INSIDE 192.168.0.0/24;
const PORT_LO 20000;           # public ports PORT_LO .. PORT_LO + PORTS - 1
const PORTS 40000;
const TRIES 4;                 # ports tried for a new flow before giving up
hash-map PAT_OUT 65536;        # inside flow -> its public port
hash-map PAT_IN 65536;         # (protocol, remote, remote port, public port) -> inside address and port

define pat-out PROTO NUM;
  match $PROTO; match ip-src $INSIDE;
    hash FLOW 64 $NUM:8 ip-src ip-dst src-port dst-port;     # this flow, from inside
    pack ME ip-src src-port;                                 # the inside end: address and port
    get map PAT_OUT %FLOW PUB;
    if PUB eq 0;
      # A new flow: its public port comes from its hash. If another flow to
      # the same remote end has that port, try the next hash (seed 1, 2, ...).
      repeat $TRIES as I;
        hash PUB buckets $PORTS seed $I $NUM:8 ip-src ip-dst src-port dst-port;
        calc add PUB $PORT_LO;
        hash BACK 64 reverse $NUM:8 ip-src src-port %PUB:16;  # the key the replies will have
        get map PAT_IN %BACK OWNER;
        if OWNER eq 0; break-repeat; end-if;                 # free
        if OWNER eq %ME; break-repeat; end-if;               # ours already
        set val PUB 0;
      end-repeat;
      if PUB eq 0; drop; end-if;                             # all tried ports are taken
      set map PAT_OUT %FLOW %PUB;
    end-if;
    hash BACK 64 reverse $NUM:8 ip-src src-port %PUB:16;
    set map PAT_IN %BACK %ME;                                # (again) for the replies
    set ip-src $WAN_IP; set src-port %PUB;
  end-match; end-match;
end-define;

define pat-in PROTO NUM;
  match $PROTO; match ip-dst $WAN_IP;
    hash BACK 64 $NUM:8 ip-src src-port dst-port;            # the same fields as BACK above
    get map PAT_IN %BACK ME;
    if ME ne 0;
      unpack %ME IN:32 INPORT:16;
      set ip-dst %IN; set dst-port %INPORT;
    end-if;
  end-match; end-match;
end-define;

when $HOOK == egress;
  pat-out tcp 6;
  pat-out udp 17;
  match icmp; match icmp-type 8; match ip-src $INSIDE;
    pack K reverse ip-src icmp-id; get ip-src IN; set map ICMP_NAT %K %IN; set ip-src $WAN_IP;
  end-match; end-match; end-match;
otherwise;
  pat-in tcp 6;
  pat-in udp 17;
  match icmp; match icmp-type 0;
    pack K ip-src icmp-id; get map ICMP_NAT %K IN; if IN ne 0; set ip-dst %IN; end-if;
  end-match; end-match;
end-when;
```

What the new commands changed:

| | Basic | With pack | With PAT |
|---|---|---|---|
| keys | built by hand, fields overlap | exact (`pack`) | 5-tuple `hash`, exact reply key |
| programs | 7 command lines to keep in step | 1 file | 1 file |
| two hosts, same source port, same server | the second takes over | the second takes over | both work |
| ports used | the inside ones | the inside ones | 20000-59999, per remote end |
| reply lookup | address only | address only | address and port (`unpack`) |

Try it (the test topology: inside hosts on `br0`, the WAN on `wan`):

```
bpfc -i wan -d egress  -p 100 -f nat-pat.bpfc
bpfc -i wan -d ingress -p 100 -f nat-pat.bpfc
bpfc -r PAT_OUT                  # the flows and their public ports
```

### 8.2 Firewall load sharing (symmetric buckets)

Stateful firewalls must see both directions of a flow. With a plain hash,
A to B and B to A would usually land on different firewalls; `symmetric`
makes them land on the same one, and `buckets` spreads the flows evenly.
Attach it to the ingress of both sides, so traffic in either direction is
spread the same way.

`fw-loadshare.bpfc`:

```
# fw-loadshare.bpfc: spread flows over $LINKS transparent (bridged) firewalls
# so that both directions of a conversation reach the same one: a stateful
# firewall drops a reply whose request it never saw. "symmetric" gives A->B
# and B->A one key; "buckets" turns the key into 0..LINKS-1, evenly.
# Attach to the ingress of the inside and the outside interface (TC or XDP)
# and fill the map with the firewall links' interface numbers:
#   bpfc -w FW_LINKS 0 $(cat /sys/class/net/fw0/ifindex)      (1, 2: fw1, fw2)
# For routed firewalls, choose a next hop per bucket and fib-lookup it.
const LINKS 3;
array-map FW_LINKS $LINKS;
match ip;
  hash B buckets $LINKS symmetric ip-src ip-dst ip-proto src-port dst-port;
  get map FW_LINKS %B IF;
  if IF ne 0; redirect %IF egress; end-if;
end-match;
```

### 8.3 Control-plane policing (prefix maps, over-rate)

A Linux router's own services need the protection that CoPP gives on a
hardware router: BGP only from configured peers, management protocols
limited so a scan or a flood cannot starve the routing daemons. The prefix
maps are filled from the shell, so adding a peer needs no recompile.

`copp.bpfc`:

```
# copp.bpfc: control-plane policing for a Linux router (TC ingress on every
# interface, e.g. bpfcd's interfaces.d/%all%/ingress): for traffic to the
# router's own addresses, BGP only from configured peers, SSH and SNMP
# limited per source address; everything else, and transit, is untouched.
#   bpfc -w LOCAL 192.0.2.254/32 1      (the router's addresses)
#   bpfc -w BGP_PEERS 192.0.2.1/32 1    (a peer; bpfc -x BGP_PEERS 192.0.2.1/32 removes it)
prefix-map LOCAL 256;
prefix-map BGP_PEERS 1024;
match ip-dst in LOCAL;
  match tcp; match port 179;
    if ip-src in BGP_PEERS; continue; end-if;
    drop;
  end-match; end-match;
  match tcp; match dst-port 22;
    match over-rate COPP_SSH ip-src 10/s burst 20; drop; end-match;
  end-match; end-match;
  match udp; match dst-port 161;
    match over-rate COPP_SNMP ip-src 50/s; drop; end-match;
  end-match; end-match;
end-match;
```

### 8.4 SYN flood guard per /24 (over-rate with a prefix)

`ip-src/24` makes the whole /24 one key, so an attacker who spreads a flood
over many addresses of a network still hits one limit. The same idea by
hand, per address, is `dist/examples/xdp/syn-guard.bpfc`: it builds a key
from a window number and the address and counts SYNs per window.

`syn-guard-subnet.bpfc`:

```
# syn-guard-subnet.bpfc: at most $LIMIT new TCP connections (SYNs) from each
# /24, so a flood spread over many addresses of one network is still caught.
# dist/examples/xdp/syn-guard.bpfc does the same per address by hand.
const LIMIT 1000/s;
match tcp; match tcp-flags SYN;
  match over-rate SYN_RL ip-src/24 $LIMIT burst 2000;
    drop;
  end-match;
end-match; end-match;
```

### 8.5 Policer (over-rate)

`dist/examples/tc/policer.bpfc` is a token bucket written out: the time of
the last packet, the credit, the cost per byte, a dozen lines of state
keeping. With `over-rate` it is one line, and it is exact under load (the
hand-written one is "approximate" because two CPUs can spend the same
credit):

`policer-rate.bpfc`:

```
# policer-rate.bpfc: policer.bpfc written with over-rate: traffic from $NET
# gets $RATE with bursts of $BURST, and the excess is dropped. Key 0 is one
# bucket for all of $NET; with "ip-src" instead, every host gets the rate.
const NET 10.1.0.0/24;
const RATE 8mbit;
const BURST 30000;
match ip; match ip-src $NET;
  match over-rate POLICE 0 $RATE burst $BURST;
    drop;
  end-match;
end-match; end-match;
```

### 8.6 Customer accounting (count, -K)

Bytes and packets per (VLAN, address) on an aggregation port: the key is
packed, so the table reads back as it was counted, ready for billing or a
"top talkers" report. Compare `dist/examples/tc/host-accounting.bpfc`, which
keys by address only.

`customer-accounting.bpfc`:

```
# customer-accounting.bpfc: packets and bytes per customer on a VLAN
# aggregation port (TC ingress of the trunk): one entry per VLAN and address,
# packed into the key, so the table reads back as it was counted:
#   bpfc -r CUST_B -K 'vlan-id ip-src'        (bytes; CUST_P: packets)
hash-map CUST_P 100000;
hash-map CUST_B 100000;
match ip;
  count CUST_P CUST_B vlan-id ip-src;
end-match;
```

```
$ bpfc -r CUST_B -K 'vlan-id ip-src' | sort -k3 -n | tail -3
101 100.64.1.20 88213004
```

### 8.7 Conversations (symmetric count)

One entry per pair of hosts, both directions added together:

`conversations.bpfc`:

```
# conversations.bpfc: bytes per conversation, both directions in one entry
# ("symmetric" puts the lower address first). Top talkers:
#   bpfc -r CONV_B -K 'ip-src ip-dst' | sort -k3 -n | tail
hash-map CONV_P 65536;
hash-map CONV_B 65536;
match ip;
  count CONV_P CONV_B symmetric ip-src ip-dst;
end-match;
```

### 8.8 Flow sampling (hash buckets, count, clone)

`dist/examples/tc/sampled-mirror.bpfc` copies one packet in N at random:
cheap, but a sampled flow is full of holes. Sampling by the flow's hash
picks whole flows: every packet of a sampled flow, in both directions, so
its counters are complete (hash-based selection, as in PSAMP, RFC 5475).

`flow-sample.bpfc`:

```
# flow-sample.bpfc: NetFlow-style sampling, one flow in $N. Every packet of a
# sampled flow, in both directions, is counted in one entry and copied to
# $COLLECTOR. The flow's hash decides, so a sampled flow is complete, unlike
# picking packets at random (sampled-mirror.bpfc). A flow's entry:
#   bpfc -r SAMPLE_B, with the key from
#   bpfc -H 'hash 64 symmetric ip-src=... ip-dst=... ip-proto=6 src-port=... dst-port=...'
const N 100;
const COLLECTOR mon0;
hash-map SAMPLE_P 65536;
hash-map SAMPLE_B 65536;
match ip;
  hash S buckets $N symmetric ip-src ip-dst ip-proto src-port dst-port;
  if S eq 0;
    count SAMPLE_P SAMPLE_B symmetric ip-src ip-dst ip-proto src-port dst-port;
    clone $COLLECTOR egress;
  end-if;
end-match;
```

### 8.9 Duplicate removal on 1+1 paths (seen)

When the same packets arrive over two links (a PRP-style redundant network,
or SMF), keep the first copy:

`dedup-simple.bpfc`:

```
# dedup-simple.bpfc: 1+1 redundant paths (the same packets arrive over two
# links): pass the first copy and drop the second. A packet is known by its
# addresses, protocol and IP identification; copies are 50 ms apart at most.
# programs/dedup does the complete job (ID rollover, statistics, ...).
match ip;
  match seen DUPS ip-src ip-dst ip-proto ip-ident within 50ms;
    drop;
  end-match;
end-match;
```

`programs/dedup` is the full program, with ID rollover, per-flow windows and
statistics; this is the idea in a few lines.

### 8.10 Two-colour marker (over-rate with else)

Instead of dropping a tenant's excess, mark it so the WAN drops it first
when it is congested:

`tenant-marker.bpfc`:

```
# tenant-marker.bpfc: a two-colour marker (TC egress to the WAN): a tenant's
# traffic within its contract is marked AF11, the excess AF13 (high drop
# precedence), so the WAN drops the excess first instead of this router.
const TENANT 10.20.0.0/16;
const CIR 50mbit;
match ip; match ip-src $TENANT;
  match over-rate TENANT_RL ip-src/16 $CIR burst 256k;
    set dscp af13;
  else;
    set dscp af11;
  end-match;
end-match; end-match;
```

### 8.11 Storm control (over-rate per MAC)

`storm-control.bpfc`:

```
# storm-control.bpfc: per-host limits for broadcast protocols, like a
# switch's storm control (TC ingress on access ports, or a bridge's ports):
# ARP and DHCP DISCOVER floods from one bad NIC or a loop are cut, keyed by
# source MAC.
match arp;
  match over-rate ARP_RL src-mac 20/s burst 40; drop; end-match;
end-match;
match udp; match dst-port 67;
  match over-rate DHCP_RL src-mac 5/s burst 10; drop; end-match;
end-match; end-match;
```

## 9. Things to know

**Map sizes.** Maps are LRU hash maps of 10000 entries unless declared:
`hash-map NAME <entries>` before the map's first use. When a map is full,
the least recently used entry makes room. For `count` that loses an old
counter; for `seen` an old key looks new again; for `over-rate` an old key
starts with a full burst. Size the maps for the number of keys you expect.

**Hash flooding.** Anyone who can send you packets can choose their
addresses and ports. The hash is not secret, so an attacker can work out
fields that collide, or fill a table with keys of their choice. For state an
attacker could use against you (a firewall's allow table), prefer `pack`
when the fields fit, keep the maps large, or give the hash a `seed` the
attacker does not know: a random number written into an array map from the
shell at boot, read into a variable, `hash K 64 seed %SEED ...`. `bpfc -H`
then needs the same `seed`.

**Atomic and not.** `count`, `seen`, `over-rate` and `calc-map` are atomic.
`get map` followed by `set map` is not: two CPUs can read the same old value.
Use it where one CPU owns a key (RSS usually keeps a flow on one CPU) or
where an occasional lost update is harmless.

**Cost.** A key costs instructions: a 5-tuple `hash` about 190, a two-field
`pack` about 50, `count` with a packed key about 100, `seen` and `over-rate`
150-200. The kernel allows a million verified instructions, so this is far
from a limit, but in an unrolled `repeat` it adds up (the PAT example's
egress program is about 4400 instructions). A key also needs stack while it
is built, 8 bytes per field (16 for an IPv6 address): a program with very
many variables may have to `free` some.

**XDP.** Everything here works in XDP programs (`-d xdp`) too, except what
XDP cannot do at all (`clone`). In XDP the `vlan-id` field reads the tag
from the frame, as there is no VLAN offload before XDP.

**IPv6.** `hash` takes IPv6 addresses; `pack`, prefix maps, `host`, `net`,
`port` and `dscp` are IPv4 only for now.

## 10. Quick reference

```
pack <VAR> [symmetric|reverse] <field>[:bits] ...                  exact, at most 64 bits
hash <VAR> <bits|buckets N> [symmetric|reverse] [seed n|%V] <field> ...   any fields, fixed size
unpack <%SRC> <VAR>:<bits> ...                                     a packed value taken apart
get flow-key <VAR> [reverse|symmetric]                             = hash 64 of the IPv4 5-tuple

count <MAP> [<BYTES_MAP>] <key...>                                 packets (and bytes) per key
match seen <MAP> <key...> within <time> [refresh]                  seen recently?
match over-rate <MAP> <key...> <rate> [burst <size>]               above the rate?
prefix-map <MAP> [entries]  /  match <ip-src|ip-dst|%V> in <MAP> [VAR]   longest-prefix match

match host <addr>  /  net <prefix>  /  port <n[-m]>  /  src-port  /  dst-port
match dscp <name|n>  /  set dscp <name|n>  /  match ecn ...  /  set ecn ...
get src-port|dst-port|dscp|ecn|ip-ttl|icmp-id|icmp-type|icmp-code <VAR>
set src-port|dst-port <n|%VAR>

bpfc -H '<hash ...|pack ...> field=value ...'                     a key, computed in the shell
bpfc -r <MAP> [-K '<fields>'] [-V '<fields>']                      a table, decoded
bpfc -R <MAP>,<MAP>... [-K '<fields>']                             several maps joined on their keys
bpfc -w <MAP> <key> <value>  /  bpfc -x <MAP> <key>                write / delete (key: number, pack/hash text, prefix)
```

Directions: plain = per direction; `reverse` = the other direction's key;
`symmetric` = one key per conversation. Fields are what is in the packet
header, whatever the hook.
