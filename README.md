# bpfc: an eBPF compiler and dataplane for network engineers

bpfc turns short, readable packet-processing programs such as `match tcp; match tcp-dst 23; drop` into eBPF bytecode, has the kernel verify them, and attaches them to network interfaces at the TC (ingress and egress) or XDP hooks. It's a single program written in plain C with no library dependencies (no LLVM, clang or libbpf), small enough for embedded routers as well as servers.

Around the compiler there are `bpfcd`, a daemon that keeps programs attached from configuration files the way a router keeps its running config; a Cisco IOS-style access-list frontend; and a set of ready-made programs, from duplicate-packet removal and flow monitoring to bandwidth-aware ECMP and a FEC/ARQ dataplane for lossy satellite links.

## Contents

- [What eBPF is, and why bpfc](#what-ebpf-is-and-why-bpfc)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Command line](#command-line)
  - [Language overview](#language-overview)
  - [Compile-time preprocessor](#compile-time-preprocessor)
  - [TC and XDP hooks](#tc-and-xdp-hooks)
- [Simple examples](#simple-examples)
- [bpfcd: keeping programs attached](#bpfcd-keeping-programs-attached)
  - [File layout and naming](#file-layout-and-naming)
  - [bpfcctl](#bpfcctl)
  - [REST API](#rest-api)
  - [Frontends: Cisco IOS access lists](#frontends-cisco-ios-access-lists)
  - [Network namespaces and containers](#network-namespaces-and-containers)
- [Included programs](#included-programs)
  - [Duplicate-packet removal (dedup)](#duplicate-packet-removal-dedup)
  - [Per-neighbor loss and capacity (linkcap)](#per-neighbor-loss-and-capacity-linkcap)
  - [Flow monitor (flowmon)](#flow-monitor-flowmon)
  - [Port-scan guard (portscan-guard)](#port-scan-guard-portscan-guard)
  - [Bandwidth-aware ECMP (ecmp)](#bandwidth-aware-ecmp-ecmp)
  - [FEC, ARQ and in-band telemetry dataplane (dataplane)](#fec-arq-and-in-band-telemetry-dataplane-dataplane)
- [Advanced examples](#advanced-examples)
- [Testing](#testing)
- [Documentation](#documentation)

---

## What eBPF is, and why bpfc

**eBPF** lets you run small programs inside the Linux kernel at fixed points, called hooks, in the packet path. Before a program runs, the kernel's *verifier* checks that it can't crash the kernel or loop forever. Once attached, the program sees every packet at its hook and can read and rewrite headers, drop the packet, redirect it to another interface, or keep state in *maps*: tables in kernel memory that the program and user-space tools share. Because this happens in the kernel, at the point a packet arrives or leaves, it's fast and needs no changes to applications or the rest of the network stack.

There are two hooks for packets:

- **TC** (traffic control), on ingress and egress of any interface. The packet is already a kernel socket buffer (skb), so a TC program can use its metadata (firewall marks, QoS priority, departure time), clone packets, and resize or re-encapsulate them freely. Several programs can be stacked on one interface by priority.
- **XDP** (eXpress Data Path), on ingress only, before the kernel has even allocated an skb. It's the earliest and fastest point, used for filtering and forwarding at line rate. An interface has one XDP program.

Normally an eBPF program is written in restricted C, compiled with clang/LLVM, and loaded with libbpf, which means a compiler toolchain, kernel headers and a build step on every system. **bpfc** replaces all of that with one small binary and a language made of networking operations:

- **Packet-oriented commands.** `match tcp-dst 23`, `set ip-src 10.0.0.30` (with the IP and TCP/UDP checksums updated for you), `push-vlan 100`, `encap-gre`, `fib-lookup` against the kernel's routing table, `redirect eth1`.
- **No toolchain on the target.** A program is a string on the command line or a text file, compiled on the spot, so routers and appliances can change their programs at run time.
- **State without code.** Counters, flow tables, rate limiters and NAT state are a single command each (`count`, `match over-rate`, `hash`/`pack` flow keys, `set map`), and they can be read and written from the shell (`bpfc -r`, `-w`).
- **Router-style operation.** `bpfcd` installs programs from `/etc/bpfc/interfaces.d`, keeps them attached across reboots and interface flaps, and reports what's running with `bpfcctl`. Access lists can be written in Cisco IOS syntax.

Typical uses are SD-WAN edge routing and policy routing, firewalls and access lists, NAT, MPLS and GRE encapsulation, QoS marking and policing, traffic accounting, link-quality measurement, and lab or security testing.

---

## Installation

```bash
make                  # build bpfc, bpfcd, bpfcctl and the ACL frontend
sudo make install     # install everything, including the bpfc-programs tools
make rpm              # or build RPMs for RHEL 9/10 (in ./rpmbuild)
make deb              # or .deb packages for Debian 12+ / Ubuntu 22.04+ (in ./debbuild)
make apk              # or Alpine packages; make arch for Arch Linux
```

You can also run `./bpfc` straight from the source tree. bpfc needs root (`CAP_NET_ADMIN` and `CAP_SYS_ADMIN`) and Linux 4.18 or later for TC programs; XDP programs need kernel 5.18+ or RHEL 9.2+. [INSTALL.md](INSTALL.md) has the full requirements, the install paths, the RPM, Debian, Alpine and Arch packages, the OpenWrt package, static builds and containers.

---

## Quick start

Drop inbound telnet on `eth0`, check that it's there, and remove it again:

```bash
sudo ./bpfc -i eth0 -p 10 "match tcp; match tcp-dst 23; drop"
tc filter show dev eth0 ingress                     # the program, attached at priority 10
sudo ./bpfc -i eth0 -p 10 -D                        # remove it
```

Each `match` opens a block that runs only when the packet matches. `drop` ends the program and drops the packet; everything else continues on its way. To have the program put back automatically after a reboot, put it in a file and let [bpfcd](#bpfcd-keeping-programs-attached) manage it:

```bash
sudo mkdir -p /etc/bpfc/interfaces.d/eth0/ingress
printf 'match tcp;\n  match tcp-dst 23;\n    drop\n' | sudo tee /etc/bpfc/interfaces.d/eth0/ingress/10.bpfc
sudo systemctl enable --now bpfcd
bpfcctl                                             # what's installed, from which file, and whether the kernel agrees
```

---

## Usage

### Command line

```bash
# Compile and attach to an interface (TC ingress by default)
sudo bpfc -i <interface> [-d ingress|egress] [-p <priority>] [-m <map_dir>] [-v] "<instructions>"
sudo bpfc -i <interface> -d egress -p 20 -f program.bpfc       # from a file

# Check a program without attaching it: compile, and have the kernel verify it
sudo bpfc -i <interface> -T -f program.bpfc

# Remove one program, or everything bpfc attached to the interface
sudo bpfc -i <interface> [-d ingress|egress] -p <priority> -D
sudo bpfc -i <interface> -c

# XDP: the interface's XDP program (generic mode), and removing it
sudo bpfc -i <interface> -d xdp "match udp; match udp-dst 9; drop"
sudo bpfc -i <interface> -d xdp -D

# Maps: read, write and delete entries
sudo bpfc -m /sys/fs/bpf -r <map> [-K '<fields>']
sudo bpfc -m /sys/fs/bpf -w <map> <key> <value>
```

| Flag | Description |
| :--- | :--- |
| `-i <iface>` | Target network interface (e.g. `eth0`). If omitted, the program is compiled to `output.bpf` locally. |
| `-d <dir>` | Hook: `ingress` (default), `egress`, or `xdp` (see [TC and XDP hooks](#tc-and-xdp-hooks)). |
| `-p <prio>` | TC filter priority (e.g. `1`). Programs on one hook run in priority order, lowest first. Running again with the same priority replaces the program atomically. |
| `-m <dir>` | Directory for pinned eBPF maps (default `/sys/fs/bpf`, e.g. `/sys/fs/bpf/my_ns/`). Programs that use the same directory share maps by name. Needed for network namespaces. |
| `-f <file>` | Read instructions from a file (`-` for stdin). `#` comments run to the end of the line. A file named `<x>.<type>` is translated by its [frontend](#frontends-cisco-ios-access-lists) first. |
| `-F <type>` | The file's type, whatever its name: `bpfc`, or a frontend's (`-F acl`). |
| `-G <file>` | Write the bpfc that a frontend generated to `file`. |
| `-T` | Check only: compile and have the kernel verify the program, then exit without attaching it or pinning maps. |
| `-c` | Cleanup mode. Atomically deletes the `clsact` qdisc, detaching all filters from the interface. With `-d xdp`, removes the XDP program. |
| `-D` | Delete only the program at `-p <prio>` on `-d <dir>` (`-d xdp`: the XDP program, no `-p`). |
| `-n <name>` | Name the TC filter and the kernel program (shown by `tc filter show` and `bpftool prog`). |
| `-I` | Print a `BPFC_INFO id=... tag=...` line after attaching, and first a `BPFC_NAME <text>` line for a program with a `name`. |
| `-r <map>` | Dump the contents of a pinned map. With `-K`/`-V`, or for a prefix map, a table: a `#` header line, then one line per entry. |
| `-K '<fields>'` | With `-r` / `-R`: decode the keys as a `pack` of these fields (`-K 'vlan-id ip-src'` prints `101 100.64.1.20 ...`). Values are then printed in decimal. |
| `-V '<fields>'` | With `-r`: decode the values the same way. |
| `-R <map>[,<map>...]` | Print pinned maps joined on their keys: `# key <map>...`, then per key the key and each map's value (`-` where it has none). For scripts. |
| `-w <map> <key> <value>` | Write a 64-bit value into a pinned map (e.g. runtime settings). The key or value may be a `pack ...`/`hash ...` text as for `-H`; for a prefix map the key is a prefix (`10.0.0.0/8`). |
| `-x <map> <key>` | Delete an entry (key as for `-w`). |
| `-H '<hash ...\|pack ...>'` | Print the key a program's `hash` or `pack` gives for these values: `bpfc -H 'hash 64 ip-src=10.0.0.1 ip-dst=10.0.0.2 ip-proto=6 src-port=1000 dst-port=80'`. See [doc/flow-tracking.md](doc/flow-tracking.md). |
| `-s <NAME>=<value>` | Set `const NAME`, overriding the program's own value. Repeatable. |
| `-L <dir>` | Search `dir` for include files (before `/etc/bpfc/include`). Repeatable. |
| `-E` | Print the program after `include`, `const`, `define`, `repeat` and `when` are expanded, then exit. |
| `-M` | Print the program file and every file it includes, one per line, then exit. |
| `-v` | Verbose mode. Prints a trace of jump offset calculations and block resolutions. |

`bpfc -h` lists every option and command, and `bpfc(8)` describes them in full.

### Language overview

A program is a list of commands separated by semicolons. In a file you can also put one command per line, indent freely, and add `#` comments. This overview covers the commands you'll use most; [doc/language.md](doc/language.md) is the complete reference.

```
# Rewrite DNS queries from the guest network to our own resolver, and count them.
match udp;                          # a block: runs only for UDP packets
  match ip-src 192.168.50.0/24;     # blocks nest
    match udp-dst 53;
      set ip-dst 192.168.1.53;      # IP and UDP checksums are updated
      calc-map add DNS_REWRITES 0 1;
    end-match;
  end-match;
end-match;
```

**Blocks.** `match <field> <value>` (or `if`) opens a block that runs when the packet's field has that value (an address or subnet, a port or port range, a MAC, a number). `end-match` closes it, and `else` gives the other branch. Protocol shorthands need no value: `match ip`, `ip6`, `arp`, `tcp`, `udp`, `icmp`, `gre`, `vlan`, `mpls`, and more. There are tcpdump-style matches too: `match host 10.0.0.1`, `match net 10.0.0.0/8`, `match port 443`, `match dscp ef`, `match tcp-flags SYN`.

**Fields.** The same field names work for `match`, `get <field> <VAR>` (copy into a variable) and `set <field> <value>` (rewrite the packet). Some of the most common:

| Layer | Fields |
| :--- | :--- |
| Ethernet | `src-mac`, `dst-mac`, `eth-proto`, `vlan-id` |
| IPv4 | `ip-src`, `ip-dst`, `ip-tos`, `dscp`, `ecn`, `ip-ttl`, `ip-proto` |
| IPv6 | `ip6-src`, `ip6-dst`, `ip6-tclass`, `ip6-flow`, `ip6-proto` |
| L4 | `tcp-src`, `tcp-dst`, `udp-src`, `udp-dst`, `src-port`, `dst-port`, `tcp-flags`, `icmp-type` |
| Other | `mpls-label`, `gre-key`, the ARP fields, raw `bytes <offset> <length>` |
| Packet metadata | `len`, `skb-mark`, `skb-priority`, `time`, `random`, `cpu` |

**Variables.** `decl NAME <bytes>` declares one, `get` fills it, and `%NAME` reads it (`set ip-dst %ORIG`). `calc add|sub|mul|div|and|or|xor|lsh|rsh <VAR> <value>` does arithmetic, and `if VAR gt 10` compares.

**Maps** keep state between packets and are shared with user space. They're pinned under `-m <dir>` by name:

| Command | Does |
| :--- | :--- |
| `count PKTS BYTES ip-src` | Atomically add 1 (and the length) to the entry for this source address |
| `calc-map add MAP <key> <value>` | Atomically add to an entry |
| `get map MAP <key> VAR` / `set map MAP <key> <value>` | Read or write an entry |
| `match over-rate MAP ip-src 100/s` | True for packets above the rate per key (a policer) |
| `match seen MAP <key> within 2s` | True when the key was seen recently |
| `hash VAR 64 ip-src ip-dst ...` / `pack VAR ip-src dst-port` | Build a flow key from packet fields ([doc/flow-tracking.md](doc/flow-tracking.md)) |

**Actions** end the program for this packet: `drop`; `continue` (go on to the next filter, also what happens at the end of the program); `accept`; `redirect <iface> [ingress|egress]`; `redirect-neigh <iface>` (fills in the next hop's MACs); and `tx` (XDP: back out of the interface it arrived on). `clone <iface>` sends a copy and carries on.

**Packet surgery.** `push-vlan`/`pop-vlan`, `push-qinq`, `encap-gre`/`decap-gre`, `encap-mpls`/`decap-mpls`, `push-eth`/`pop-eth`, `add-bytes`/`del-bytes`, `ip-frag`/`ip-defrag`, `recalc-tcp-csum`. `fib-lookup` asks the kernel's routing table for the next hop (`%FIB_IFINDEX`, `%FIB_DMAC`, ...).

### Compile-time preprocessor

Before compiling, bpfc expands constants, macros, includes and loops, so one file can serve many interfaces and be tuned without editing it. `bpfc -E` prints the expanded program.

| Keyword | Does |
| :--- | :--- |
| `const NAME value` | Defines `$NAME`. `-s NAME=value` on the command line overrides it. |
| `define NAME [PARAM ...]` ... `end-define` | A macro, used like a command: `NAME arg ...` |
| `include file` | Reads a file once: next to this one, then the `-L` directories, then `/etc/bpfc/include` |
| `repeat N [as I]` ... `end-repeat` | Copies the body N times with `$I` = 0, 1, ... (unrolled, so it loads on any kernel) |
| `when <expr>` ... `otherwise` ... `end-when` | Keeps one branch, decided at compile time |
| `name text` | A name for people, shown by `bpfcctl` |
| `$(expr)` | Constant arithmetic: `$(14 + 20)` |
| `$IFNAME`, `$IFINDEX`, `$IFMAC`, `$IFKIND`, `$HOOK`, `$XDP`, `$L3OFF` | The interface and hook the program is compiled for |

```
const LIMIT 100;
define allow-port PORT;
  match tcp-dst $PORT; accept; end-match;
end-define;

match tcp;
  allow-port 22;
  allow-port 443;
  match over-rate SYNS_$IFNAME ip-src $LIMIT/s; drop; end-match;
end-match;
```

`bpfc -i eth0 -s LIMIT=50 -f guard.bpfc` compiles it with a different limit. See [Constants, Macros, Includes and Unrolled Loops](doc/language.md#constants-macros-includes-and-unrolled-loops) for all of it.

### TC and XDP hooks

**TC** (`-d ingress`, the default, or `-d egress`) attaches the program as a `clsact` filter at `-p <priority>`. Several programs can share a hook, and run lowest priority first while each ends with `continue`. TC programs can use every command except `tx`. Note that TC ingress runs after GRO (the kernel merging TCP segments): a filter here sees merged packets, and covers bugs in TCP/IP processing but not in GRO or the driver. For those, use XDP.

**XDP** (`-d xdp`) compiles the same language into an XDP program and attaches it as the interface's XDP program, in generic (skb) mode for now (native/driver mode later). It runs before GRO, TC and the stack. One program per interface; attaching replaces it atomically.

* `accept` and `continue` pass the packet on (XDP_PASS), `drop` is XDP_DROP, `redirect <iface>` sends it out of that interface, and `tx` (XDP only) sends it back out of the interface it came in on.
* Checksum-aware rewrites (`set ip-src`, ports, `ip-tos`, ...) update the IP and TCP/UDP checksums incrementally, as on TC. XDP sees complete checksums; a packet a local socket sent through a veth pair may carry a partial one (CHECKSUM_PARTIAL), which an L4 rewrite corrupts once the packet is forwarded: turn tx checksum offload off on such senders (`ethtool -K <dev> tx off`).
* VLAN tags are in the packet: `match vlan`/`qinq`, `get`/`match vlan-id` read them there, `set vlan-id` rewrites the id in the tag (keeping priority and DEI; pushes an 802.1Q tag when there is none), and `push-`/`pop-vlan` insert or remove the 4-byte tag after the MAC addresses. A NIC that strips tags (`rxvlan` offload) may hand generic XDP packets without them.
* Resizing works: `add-head-bytes`, `add-bytes`/`del-bytes`, `add-l2-bytes`/`del-l2-bytes`, `push-`/`pop-eth`, `push-`/`pop-vlan`, `push-qinq`, `encap-`/`decap-mpls`, `encap-`/`decap-gre`, `insert-l2`/`remove-l2`/`strip-l2` and `set len`, so the [MPLS pseudowire](#3-mpls-pseudowires) examples run as XDP programs too. The packet grows or shrinks at the front with `bpf_xdp_adjust_head` (up to 255 bytes at a time; generic mode has 256 bytes of headroom) and at the end with `bpf_xdp_adjust_tail`; inserted bytes are zero, as on TC. Growing at the end needs tailroom, which generic mode may not have.
* Commands that need an skb are a compile error naming the command: `ip-frag`, `ip-defrag`, `clone`, `redirect-neigh`, `reclassify`, and the skb fields (`skb-mark`, `skb-hash`, `skb-priority`, `gso-segs`, `skb-cb`, `protocol`, `tstamp`, `set queue`). `get len`, `skb-ingress`/`skb-ifindex` (the ingress interface) and `queue` (the receive queue) work.
* `$XDP` (1 in an XDP program) and `$HOOK` (`ingress`, `egress`, `xdp`) let one file serve several hooks: `when $XDP == 0; set skb-mark 5; end-when`.

**Tunnel devices.** On devices without an Ethernet header (gre, ipip, sit, wireguard, tun, PPP) packets start with the IP header. bpfc reads the IP and L4 fields from there by itself (`$L3OFF` is 0 instead of 14), and Ethernet fields and commands are a compile error. See `$L3OFF` in [doc/language.md](doc/language.md#constants-macros-includes-and-unrolled-loops).

---

## Simple examples

Each of these is a complete program. Attach it with the command shown, and remove it with `bpfc -i <iface> -p <prio> -D` (add `-d egress` for egress). Map contents are read with `bpfc -m /sys/fs/bpf -r <map>`.

**Block a network.** Drop everything from 198.51.100.0/24 arriving on `eth0`:

```bash
bpfc -i eth0 -p 10 "match ip-src 198.51.100.0/24; drop"
```

**Rate-limit ping.** Allow each source 10 echo requests a second and drop the rest:

```bash
bpfc -i eth0 -p 20 "match icmp; match icmp-type 8; match over-rate PING ip-src 10/s; drop"
```

**Count traffic per host.** Packets and bytes per source address, in maps `PKTS` and `BYTES`:

```bash
bpfc -i eth0 -p 30 "match ip; count PKTS BYTES ip-src"
bpfc -m /sys/fs/bpf -r PKTS -K 'ip-src'       # decode the key as an address
# ip-src value
127.0.0.1 16
```

**Mark voice for QoS.** Set DSCP EF on SIP signalling leaving `wan0`, so the queues along the path can prioritise it:

```bash
bpfc -i wan0 -d egress -p 10 "match udp; match dst-port 5060; set dscp ef"
```

**Mirror DNS to a capture host.** Send a copy of every DNS packet to `mon0`, and let the original continue:

```bash
bpfc -i eth0 -p 40 "match udp; match port 53; clone mon0 egress"
```

**A program file with a constant.** Files can be commented, indented and parameterised. This one drops a configurable network and counts the drops per interface:

```
# block.bpfc: drop traffic from a blocked network, and count what was dropped.
const BLOCKED 198.51.100.0/24;
name block $BLOCKED on $IFNAME;

match ip; match ip-src $BLOCKED;
  calc-map add DROPS_$IFNAME 0 1;
  drop;
end-match; end-match;
```

```bash
bpfc -i eth0 -p 10 -f block.bpfc                              # as written
bpfc -i eth0 -p 10 -s BLOCKED=203.0.113.0/24 -f block.bpfc    # another network
bpfc -i eth0 -E -f block.bpfc                                 # see what it expands to
bpfc -m /sys/fs/bpf -r DROPS_eth0
```

Copied to `/etc/bpfc/interfaces.d/%all%/ingress/10.bpfc`, bpfcd puts it on every interface, each with its own `DROPS_<interface>` map.

**NAT, two ways.** [Advanced example 4](#4-network-address-translation-nat) builds a NAT the long way, with the flow keys assembled by hand. `dist/examples/flow/nat-pack.bpfc` does the same in a few lines with `pack`, and [doc/flow-tracking.md](doc/flow-tracking.md#81-nat-three-ways) walks through both, and a third version with port translation.

---

## bpfcd: keeping programs attached

`bpfcd` keeps the programs in `/etc/bpfc/interfaces.d` attached, so they survive reboots and interfaces being re-created. You edit files and reload, much as you'd edit a router's configuration:

```bash
mkdir -p /etc/bpfc/interfaces.d/eth0/ingress
printf 'match tcp;\n  match tcp-dst 23;\n    drop\n' > /etc/bpfc/interfaces.d/eth0/ingress/100.bpfc
systemctl enable --now bpfcd
systemctl reload bpfcd        # after changing files (or: bpfcctl reload)
bpfcctl                       # what is installed, from which file, and whether the kernel agrees
```

See `bpfcd(8)`, `bpfcctl(8)` and `bpfc.conf(5)` for the details.

### File layout and naming

```
/etc/bpfc/interfaces.d/<interface>/ingress/<priority>.bpfc
/etc/bpfc/interfaces.d/<interface>/egress/<priority>.bpfc
/etc/bpfc/interfaces.d/<interface>/xdp.bpfc                        the interface's XDP program
/etc/bpfc/interfaces.d/%all%/{ingress,egress}/<priority>.bpfc      every interface
/etc/bpfc/interfaces.d/%<kind>%/{ingress,egress}/<priority>.bpfc   every interface of that kind
/etc/bpfc/interfaces.d/{<interface>,%all%,%<kind>%}/xdp.bpfc
/etc/bpfc/interfaces.d/<interface>/ingress/<priority>.<type>       translated by a frontend (10.acl)
```

* **The file name is the priority.** `ingress/100.bpfc` is attached at TC priority 100 on ingress, so programs on a hook run in the order of their file names' numbers. `xdp.bpfc` has no priority, since an interface has one XDP program (`bpfcctl show eth0 xdp`). It's attached in generic mode and runs before TC ingress. Templates, empty files, reloads, failures, adoption and external changes work for it as for TC.
* **Other file types.** `<priority>.<type>`, such as `10.acl`, is translated into bpfc by the frontend for that type ([below](#frontends-cisco-ios-access-lists)).
* **All interfaces, or all of a kind.** `%all%/` applies to every interface, and `%<kind>%/` to every interface of that kind as `ip -d link` shows it (`%veth%`, `%gre%`, `%vxlan%`, `%wireguard%`, `%tun%`, ...). `%nic%` covers devices without a kind (physical NICs), and `%lo%` loopback. A template is compiled once per interface, with `$IFNAME`, `$IFINDEX`, `$IFTYPE` and `$IFKIND` set for it, and new interfaces get the programs when they appear.
* **The most specific file wins.** For each direction and priority, bpfcd uses `<interface>/` first, then `%<kind>%/`, then `%all%/`. Other priorities still apply.
* **Opting out.** An empty file (or one with only comments) at a more specific level means nothing at that priority there. For example, an empty `eth1/ingress/100.bpfc` exempts eth1 from `%all%/ingress/100.bpfc`; `bpfcctl` shows it as `excluded`.
* **Tunnel devices.** On devices without an Ethernet header (gre, ipip, sit, wireguard, tun), a template that uses Ethernet fields (MACs, VLAN, ARP, MPLS) fails to compile (status `failed`; the other interfaces still get it). Guard that part with `when $L3OFF == 14`, or put an empty file for that priority in `%gre%/`, `%wireguard%/`, ...
* **Include files** go outside `interfaces.d`, for example in `/etc/bpfc/include`, or bpfcd will try to install them as programs.
* **Stacked devices** (a bridge and its ports, a bond and its slaves) see the same packet more than once.

How bpfcd handles changes:

* **Reload** (`systemctl reload bpfcd` or `bpfcctl reload`). New and changed files are installed (an atomic replace at the same priority), and deleted files are detached. A file is only re-hashed when its mtime changes, and only reinstalled when its SHA-256 differs. A program that uses `include` is hashed together with the files it includes (as listed by `bpfc -M`) on every reload, so editing a shared library reinstalls every program that uses it.
* **Failures.** If a new version of a file doesn't compile or the verifier rejects it, the previous program stays attached (status `failed-kept`) and `bpfcctl show` prints the error. With `on_failure = remove` in `bpfc.conf` (or `option on-failure remove` in the program) the priority is left empty instead.
* **Interfaces.** Programs are installed when a configured interface appears, and re-installed when it is re-created.
* **External changes.** If something else removes or replaces a managed program, bpfcd reinstalls it or only logs it, per `on_external_change` in `/etc/bpfc/bpfc.conf`.
* **Tracking.** Each program's id and tag are recorded with its file path and hash in `/run/bpfc/state`, and filters are named `bpfcd:<iface>/<dir>/<prio>`. A restarted bpfcd adopts the programs that are still attached instead of reinstalling them.

### bpfcctl

| Command | Shows |
| :--- | :--- |
| `bpfcctl` (or `bpfcctl status [-a] [-l] [-j]`) | One line per program: interface, hook, priority, name, status, kernel program id and tag, a kernel check, and the file. `-a` also lists filters bpfcd doesn't manage, `-j` prints JSON. |
| `bpfcctl show <iface> <ingress\|egress> <prio>` | One program in detail: its record, its source with line numbers and, for a failed program, the bpfc output and verifier log. `--source` adds the bpfc a frontend generated, and `--bytecode` the program as the kernel holds it. |
| `bpfcctl show <iface> xdp` | The interface's XDP program, the same way |
| `bpfcctl reload [--no-wait]` | Rescan the files and report failures |
| `bpfcctl show access-lists [name] [interface <iface>]` | IOS-style access lists with per-entry hit counts |
| `bpfcctl top [n [seconds]]` | The busiest access-list entries right now |
| `bpfcctl log [-f]` | Access-list `log` entries, IOS-style (`%SEC-6-IPACCESSLOGP`) |
| `bpfcctl clear access-list counters [name]` | Reset the hit counters |
| `bpfcctl -n <netns> ...`, `bpfcctl --all-netns` | The same for a network namespace instance, or for all of them |

Here `flowmon` from `%all%` is on every interface, two interfaces opt out of it with empty files, and `wan1` has a program of its own on ingress (abridged):

```
# bpfcctl
bpfcd: running (pid 120, version 0.1.1), started 2026-11-23 10:46:19, last reload 2026-11-23 10:47:21
programs: /etc/bpfc/interfaces.d    external changes: reinstall

IFACE     DIR       PRIO  NAME                                             STATUS                 PROG  TAG               KERNEL    FILE
lo        ingress     10  flowmon ingress: IPv4 flow and TCP loss monitor  installed              2550  ddccc0a2568fece4  ok        %all%/ingress/10.bpfc
lo        egress      10  flowmon egress: IPv4 flow and TCP loss monitor   installed              2551  ddccc0a2568fece4  ok        %all%/egress/10.bpfc
net0      ingress     10  -                                                excluded                  -  -                 -         net0/ingress/10.bpfc
net0      egress      10  -                                                excluded                  -  -                 -         net0/egress/10.bpfc
net0.501  ingress     10  flowmon ingress: IPv4 flow and TCP loss monitor  installed              2565  ddccc0a2568fece4  ok        %all%/ingress/10.bpfc
net0.501  egress      10  flowmon egress: IPv4 flow and TCP loss monitor   installed              2566  ddccc0a2568fece4  ok        %all%/egress/10.bpfc
wan0      ingress     10  -                                                excluded                  -  -                 -         wan0/ingress/10.bpfc
wan0      egress      10  -                                                excluded                  -  -                 -         wan0/egress/10.bpfc
wan1      ingress     10  -                                                installed              2549  cbfebffddcfc1437  ok        wan1/ingress/10.bpfc
wan1      egress      10  flowmon egress: IPv4 flow and TCP loss monitor   installed              2552  ddccc0a2568fece4  ok        %all%/egress/10.bpfc
wan1.100  ingress     10  flowmon ingress: IPv4 flow and TCP loss monitor  installed              2557  ddccc0a2568fece4  ok        %all%/ingress/10.bpfc
wan1.100  egress      10  flowmon egress: IPv4 flow and TCP loss monitor   installed              2558  ddccc0a2568fece4  ok        %all%/egress/10.bpfc
```

The status is `installed`, `installing`, `pending-iface` (the interface doesn't exist yet), `failed`, `failed-kept`, `removed-externally`, `replaced-externally`, `reinstall-limit` or `excluded`. KERNEL is `ok` when the kernel has exactly the recorded program, and `MISSING` or `DIFFERS` when it doesn't.

`bpfcctl show` gives one program in detail, followed by its source:

```
# bpfcctl show wan1.100 ingress 10
wan1.100 ingress priority 10
  name:       flowmon ingress: IPv4 flow and TCP loss monitor
  status:     installed
  file:       /etc/bpfc/interfaces.d/%all%/ingress/10.bpfc
  sha256:     7dc4215cd694a8c5dc58adeada8cac4a0d1a7adc9af4c9b98f020aa405800bbf
  program:    id 2557  tag ddccc0a2568fece4  1704 insns
  kernel:     ok
  installed:  2026-11-23 10:47:21   last change: 2026-11-23 10:47:21

Source
   1  # BPFC IPv4 flow monitor, TC ingress and egress (egress/10.bpfc includes this
   2  # file). Read with bpfc-flows(8).
  ...
```

### REST API

The REST API is off by default. With `rest_socket = /run/bpfc/bpfcd.sock` in `bpfc.conf`, bpfcd serves HTTP on that unix socket. The socket is owned by `root:bpfc` with mode `0660`, so add users to the `bpfc` group; anyone who can connect can change programs.

| Request | Does |
| :--- | :--- |
| `GET /` | The status as JSON (the same as `bpfcctl status --json`) |
| `GET /interfaces/<if>` | One interface |
| `GET /interfaces/<if>/<ingress\|egress>/<prio>`, `/interfaces/<if>/xdp` | A program file, as a JSON array of lines |
| `POST` / `PUT` on the same | Write the file and install it |
| `DELETE` on the same | Remove it |

Writes are checked with `bpfc -T` first and rolled back if installing fails; `?dry-run` only checks. Files written through the API live in `/var/lib/bpfc/interfaces.d` and override the same file in `/etc/bpfc/interfaces.d`.

```bash
curl --unix-socket /run/bpfc/bpfcd.sock http://localhost/interfaces/eth0
curl --unix-socket /run/bpfc/bpfcd.sock -X POST -d '["match tcp;", "  match tcp-dst 23;", "    drop"]' \
     http://localhost/interfaces/eth0/ingress/10
curl --unix-socket /run/bpfc/bpfcd.sock -X DELETE http://localhost/interfaces/eth0/ingress/10
```

### Frontends: Cisco IOS access lists

A program file need not be bpfc. `<priority>.<type>` files are translated by a *frontend*: an executable named after the type, looked up as `/etc/bpfc/frontends/<type>`, then `/usr/libexec/bpfc/frontends/<type>`. It can be a shell script, a Python script or a binary (the contract is under FRONTENDS in `bpfc(8)`). bpfcd manages such files like `.bpfc` ones, and `bpfcctl show --source` shows the bpfc they were translated into.

bpfc ships one frontend, `acl`, for IOS access lists:

```
# /etc/bpfc/interfaces.d/eth0/ingress/10.acl
ip access-list extended EDGE-IN
 10 deny ip 10.0.0.0 0.255.255.255 any log
 20 permit tcp any 203.0.113.0 0.0.0.255 established
 30 permit tcp any host 203.0.113.25 eq smtp
 40 deny ip any any log
```

```
bpfcctl show access-lists              # Extended IP access list EDGE-IN / 20 permit ... (88213 matches)
bpfcctl top                            # the busiest entries right now
bpfcctl log -f                         # %SEC-6-IPACCESSLOGP: list EDGE-IN denied tcp ...
bpfcctl clear access-list counters EDGE-IN
```

It supports standard, extended, IPv6 and MAC lists, numbered and named; object groups (shared ones go in `/etc/bpfc/acl.d`); reflexive lists (`reflect`/`evaluate`); `established`, TCP flags, fragments, DSCP/precedence/TTL; and `log` and `log-input`. Anything bpfc can't apply exactly is an error, and a list that fails to load leaves the previous one running. [doc/firewall.md](doc/firewall.md) is the guide, and the examples are in `dist/examples/acl`.

### Network namespaces and containers

**Network namespaces.** `bpfcd -n <name>` (usually `systemctl enable --now bpfcd-netns@<name>`) manages namespace `<name>` from `/etc/bpfc/netns/<name>/` (`bpfc.conf`, `interfaces.d/`), with its own state (`/run/bpfc/netns/<name>`) and pinned maps (`/sys/fs/bpf/netns/<name>`). The namespace is `/run/netns/<name>`, or `netns_path` (a namespace file or a symlink to one, re-followed every second), or `netns_veth` (the namespace holding the peer of a host-side veth: a pod or container). bpfcd waits for a namespace that isn't there yet, moves its programs when the path or veth comes to point at another namespace, and lets a deleted one be freed. `bpfcctl -n <name>`, `bpfcctl --all-netns` and the `-n` option of the bpfc-programs tools work on it, and `bpfcctl -n <name> exec <command>` runs a command inside it. The main bpfcd manages only the default namespace.

```bash
mkdir -p /etc/bpfc/netns/pod1/interfaces.d/eth0/ingress
echo 'netns_veth = veth3f2a1c' > /etc/bpfc/netns/pod1/bpfc.conf   # the pod's host-side veth
cp drop-telnet.bpfc /etc/bpfc/netns/pod1/interfaces.d/eth0/ingress/100.bpfc
systemctl enable --now bpfcd-netns@pod1
bpfcctl -n pod1
```

**Containers (no systemd).** The `bpfc-container` package adds `/usr/sbin/bpfcd-entrypoint`, which runs bpfcd as the container's PID 1. Neither package requires systemd, and settings can be passed as `BPFCD_*` environment variables. See [dist/container/README.md](dist/container/README.md) for an example Containerfile and run options, and [INSTALL.md](INSTALL.md#static-binaries) for statically linked builds for images without a matching libc.

---

## Included programs

These are complete applications built on bpfc. They come in the optional `bpfc-programs` package (`dnf install bpfc-programs`; `make install` installs them too, or `make install-programs` alone), one folder per program under `programs/` in the source. Most have a generator, which writes `.bpfc` files into `/etc/bpfc/interfaces.d` for bpfcd to install, and a status tool that reads the program's maps. The tools are bash scripts and also run in place from a source tree. They're listed here from the simplest to the most involved.

| Program | What it does | Tools |
| :--- | :--- | :--- |
| [dedup](#duplicate-packet-removal-dedup) | Drops duplicate IPv4 packets, e.g. on 1+1 redundant paths | `bpfc-dedup` |
| [linkcap](#per-neighbor-loss-and-capacity-linkcap) | Loss, delay and capacity per neighbor, from packet accounting | `bpfc-linkcap-gen`, `bpfc-linkcap-status` |
| [flowmon](#flow-monitor-flowmon) | Per-flow traffic, and TCP retransmissions and loss | `bpfc-flows` |
| [portscan-guard](#port-scan-guard-portscan-guard) | Detects and blocks port scans | `bpfc-portscanctl` |
| [ecmp](#bandwidth-aware-ecmp-ecmp) | Balances flows over multipath routes by measured load | `bpfc-ecmp-gen`, `bpfc-ecmp-status` |
| [dataplane](#fec-arq-and-in-band-telemetry-dataplane-dataplane) | FEC, retransmission and telemetry for lossy point-to-point links | `bpfc-dataplane-gen`, `bpfc-dataplane-status` |

### Duplicate-packet removal (dedup)

Drops the second copy of an IPv4 packet (same source, destination, protocol and IP ID, and the same length and TCP/UDP checksum). Include `dedup-iface.bpfc` (one table per interface and hook, ingress or egress) or `dedup-global.bpfc` (one table shared by the ingress of several interfaces, for 1+1 redundant paths), then call `dedup` inside the matches for the traffic that can be duplicated. Fragments pass untouched. An earlier packet stops counting after `DD_MS` milliseconds, once the sender's ID has advanced `DD_IDS` (rollover), or after `DD_PKTS` packets of its flow. The include files are installed in `/etc/bpfc/include`.

```
include dedup-iface.bpfc;
match udp; match udp-dst 5000-5010; dedup; end-match; end-match;
```

```bash
bpfc-dedup                 # counters, last duplicate and recent duplicates per table; -j for JSON, -z to reset
```

See [programs/dedup/README.md](programs/dedup/README.md).

### Per-neighbor loss and capacity (linkcap)

Every unicast IP packet leaving an interface is counted per neighbor: the next hop's MAC on Ethernet, the far end of a point-to-point link such as GRE, PPP or WireGuard, or the outer address on multipoint GRE. At each report interval, a clone of a packet becomes a small report with the cumulative counts and a timestamp. The neighbor answers with what it received by then, and the sender gets loss, delivered rate, queueing delay (no clock synchronisation needed) and RTT per interval. The status tool turns these into a capacity estimate: the median rate delivered while the queueing delay is above a threshold, or a lower bound while it isn't. Loss without a rise in delay is link loss, not congestion. Both ends must run it, and nothing is sent on idle links.

```bash
bpfc-linkcap-gen -i eth0 -i gre1            # /etc/bpfc/interfaces.d/<if>/{ingress/5,egress/60000}.bpfc
bpfc-linkcap-gen -i wan0 --profile leo      # also: default, geo
systemctl reload bpfcd
bpfc-linkcap-status                         # one row per neighbor: state, capacity, lower bound, rate, loss, delay
bpfc-linkcap-status -1                      # key=value per neighbor, for a shaper (-j: JSON)
bpfc-linkcap-status set eth0 delay-threshold 20ms
```

See [programs/linkcap/DESIGN.md](programs/linkcap/DESIGN.md) for the frames, the samples and the limits.

### Flow monitor (flowmon)

A TC program for both hooks of every interface that records each IPv4 flow: bytes and packets in each direction, first and last seen, the interfaces and MACs it used, its VLAN and DSCP. For TCP it also tells retransmissions (data that already passed this point: loss downstream, or spurious) from loss (holes in the sequence space: loss upstream), and doesn't count reordering within `FM_REORDER_MS` (default 10 ms) as loss. `bpfc-flows` shows the flows like `top`, with rates since the previous sample.

```bash
cp -r /usr/share/doc/bpfc-programs/flowmon/examples/interfaces.d/%all% /etc/bpfc/interfaces.d/
systemctl reload bpfcd
bpfc-flows                                   # flows seen in the last 60 s, busiest first
bpfc-flows -w 2 --limit 20                   # refresh every 2 s
bpfc-flows -t --filter proto=tcp --sort retrans-pct    # TCP retransmission and loss columns
bpfc-flows --filter src=10.1.0.0/16 --filter dscp=ef --json
```

`bpfc-flows --help` lists the sort keys and filters. The [bpfcctl](#bpfcctl) output above shows flowmon installed from `%all%`.

### Port-scan guard (portscan-guard)

Detects IPv4 TCP and UDP port scans. Each source's distinct `{protocol, destination port}` contacts within a scan window add to a score, and management and rarely legitimate ports weigh more. A source whose score crosses the threshold can be blocked for a time that grows with repeat offences. It starts in monitor mode. Once the threshold is tuned for your network, switch it to silent drops or TCP resets.

```bash
cp /usr/share/doc/bpfc-programs/portscan-guard/examples/interfaces.d/eth0/ingress/10.bpfc \
   /etc/bpfc/interfaces.d/eth0/ingress/10.bpfc
systemctl reload bpfcd
bpfc-portscanctl status                     # sources, scores, recent services, block times
bpfc-portscanctl set threshold 20
bpfc-portscanctl set mode block             # monitor | block | reset
bpfc-portscanctl unblock 198.51.100.7
```

The header of the program file describes the scoring and its maps.

### Bandwidth-aware ECMP (ecmp)

A routing layer for a single router. It balances flows over the next hops of the kernel's multipath routes by measured load, with interface preferences per traffic class. It needs nothing from its neighbours and is independent of the FEC dataplane. Packets change only as in any router (TTL, IP checksum, MACs). IPv4.

```bash
sysctl -w net.ipv4.ip_forward=1 net.ipv4.fib_multipath_hash_policy=1

bpfc-ecmp-gen --member eth1=1g --member eth2=1g --member wg0=100m --ingress eth0 \
              --mode l4 --shed 70 --move 90 --clear 80 \
              --policy "src 10.1.0.0/16 dscp 46 prefer wg0,eth1"
systemctl reload bpfcd

bpfc-ecmp-status                       # load per interface
bpfc-ecmp-status flows -n 20           # bit/s, path and last decision per flow
bpfc-ecmp-status events                # recent decisions
bpfc-ecmp-status bw wg0 80m            # new bandwidth, at once (an outside estimator can do this)
bpfc-ecmp-status set shed 60           # thresholds and timers at run time
```

Every packet re-checks that its flow's interface is still a member of the route, so a withdrawn next hop is noticed on the next packet. See [programs/ecmp/DESIGN.md](programs/ecmp/DESIGN.md).

### FEC, ARQ and in-band telemetry dataplane (dataplane)

`bpfc-dataplane-gen` generates bpfc programs for a point-to-point link, and both ends run them. Every IPv4 packet for the remote prefixes given with `--protect` gets an 8-byte shim with a sequence number and timestamp. On a Layer-2 link the shim goes after the Ethernet header (EtherType 0x88B5). It can go inside UDP instead: `--carrier udp` adds an outer IPv4/UDP header to the peer, for routed paths, the internet and NAT, and `--carrier udp-inline` puts UDP after the packet's own IP header, for a private routed WAN.

The receiver measures loss, reordering, duplicates, jitter and queueing delay (no clock synchronisation needed) and reports back once a second. When loss crosses a threshold, the sender adds XOR parity (forward error correction) scaled to the loss, and turns it off again after a cool-down. Lost packets are also retransmitted from a short buffer (ARQ). Packet-pair probes estimate the link capacity; on links that deliver in frames, such as Starlink, it uses probe trains and a median (`--probe-train 20ms --capacity-percentile 50`, set in the `leo` profile). Each interface has its own maps.

Profiles set the defaults for a kind of link: `direct`, `wan`, `geo` and `leo` are built in, and your own go in `/etc/bpfc/dataplane/profiles.d/`. `--link-rate` and `--rtt` size the retransmit ring and windows.

```bash
bpfc-dataplane-gen -i eth0 --profile geo   # writes /etc/bpfc/interfaces.d/eth0/{egress,ingress}/*.bpfc
bpfc-dataplane-gen --list-profiles
bpfc-dataplane-gen --show-profile geo --rtt 650ms   # effective settings and buffer sizes
bpfc-dataplane-gen -i eth0 --setup-hints   # MTU / offload settings for the link
systemctl reload bpfcd
bpfc-dataplane-status                      # one table row per interface (FRR style)
bpfc-dataplane-status eth0 detail          # the full report; also -d
bpfc-dataplane-status json                 # the same data as JSON; also -j (-1: key=value lines)
bpfc-dataplane-status set eth0 fec-threshold 2
# over the internet, the site behind (CG)NAT names the public one; the public one learns it
bpfc-dataplane-gen -i wan0 --profile leo --carrier udp --peer 203.0.113.10 --protect 10.1.0.0/16   # NAT side
bpfc-dataplane-gen -i eth0 --profile leo --carrier udp --peer learn --protect 10.2.0.0/16          # public side
```

The built-in profiles are installed in `/usr/share/bpfc/dataplane/profiles/`, and DESIGN.md with example programs in `/usr/share/doc/bpfc-programs/dataplane/`. See [programs/dataplane/DESIGN.md](programs/dataplane/DESIGN.md) for the wire format, the algorithms and the limits.

---

## Advanced examples

Longer programs for real network problems. Examples 1–5 are written out the long way, command by command. Examples 6–19 use the preprocessor and are kept as files in `dist/examples/` (installed in `/usr/share/doc/bpfc/examples/`). The test suite runs the NAT example (4) and the example files (6–18) exactly as they're shown here.

### 1. ARP Spoofing / Reflection
Intercept an ARP Request, flip it to a Reply, dynamically swap addresses, and reflect it out the same interface.
```bash
./bpfc -i eth0 -p 5 -d ingress "match arp; match arp-oper 1; \
    get arp-sha S_MAC; get arp-spa S_IP; get arp-tpa T_IP; \
    set arp-oper 2; \
    set arp-tha %S_MAC; set arp-tpa %S_IP; \
    set arp-sha aa:bb:cc:dd:ee:ff; set arp-spa %T_IP; \
    redirect eth0 egress"
```

### 2. SD-WAN Policy Routing (FIB Lookup + GRE)
Route UDP 5060 (VoIP) out a fast link, and GRE tunnel everything else via the routing table.
```bash
./bpfc -i eth0 -d ingress "match ip; \
    match udp-dst 5060; \
        set ip-tos 184; \
        redirect-neigh eth1; \
    end-match; \
    encap-gre ip-src 10.0.0.1 ip-dst 10.99.0.1 key 123; \
    fib-lookup output; \
    match val %FIB_RESULT eq 0; \
        redirect-neigh %FIB_IFINDEX; \
    end-match; \
    continue"
```

### 3. MPLS pseudowires
Encapsulate all packets on interface eth1 in an MPLS pseudowire with label 16 and next-hop label 20, and send them to 10.0.0.6. The labels are built by hand to show the bit layout (label, traffic class, bottom of stack, TTL); `encap-mpls label 20 bos 0` pushes one in a single command. The program is read from stdin (`-f -`), so it can carry `#` comments:
```bash
./bpfc -i eth1 -d ingress -f - <<'EOF'
decl MPLS1 4;
decl MPLS2 4;
fib-lookup 10.0.0.6;
match val %FIB_RESULT eq 0;
  add-head-bytes 22;                  # room for a new Ethernet header (14) and two labels (8)
  # Next-hop label 20: label, traffic class 0, bottom of stack 0, TTL 225
  set val MPLS1 20;
  calc lsh MPLS1 3; calc or MPLS1 0;  # traffic class
  calc lsh MPLS1 1; calc or MPLS1 0;  # bottom of stack: not the last label
  calc lsh MPLS1 8; calc or MPLS1 225;
  calc bswap MPLS1;
  # Pseudowire label 16: bottom of stack 1
  set val MPLS2 16;
  calc lsh MPLS2 3; calc or MPLS2 0;
  calc lsh MPLS2 1; calc or MPLS2 1;
  calc lsh MPLS2 8; calc or MPLS2 225;
  calc bswap MPLS2;
  set bytes 14 4 %MPLS1;
  set bytes 18 4 %MPLS2;
  set eth-proto 0x8847;
  set dst-mac %FIB_DMAC;
  set src-mac %FIB_SMAC;
  redirect %FIB_IFINDEX egress;
end-match;
EOF
```

Decapsulate pseudowire packets and send them to interface eth2, assuming the PE router has already stripped next-hop label `20`:
```bash
./bpfc -i eth0 -d ingress "match mpls; \
        match mpls-label 16; \
        del-bytes 0 18; \
        redirect eth2 egress"
```

If control words are desired, change `add-head-bytes 22` to `add-head-bytes 26` and `del-bytes 0 18` to `del-bytes 0 22` to account for the 4-byte control word.

The same programs work as XDP programs: use `-d xdp` instead of `-d ingress` (`./test.sh mpls-xdp` runs the pseudowire test that way).

Note: the MPLS encapsulation above doesn't work with TCP Generic Receive Offload (GRO) or TCP Segmentation Offload (TSO). These combine several TCP segments into a single sk_buff, which is then encapsulated as one MPLS packet, often larger than the interface MTU. To avoid this, disable GRO and TSO on the interface with `ethtool -K eth1 tso off gro off`.

### 4. Network Address Translation (NAT)


Outgoing:
* Create a `FLOW_KEY` variable using layer-3 and layer-4 information that is unique to flow and store the source IP address.
* Change the packet source IP address to the WAN facing IP address. 

Incoming:
* Lookup the original source IP address using the same `FLOW_KEY` fields, but reverse source & destination where appropriate.
* Change the packet destination IP address to the original source IP address referenced by `FLOW_KEY`

This implementation uses the normal Linux routing FIB, so there is no need to do FIB lookups or redirection in eBPF.

The same NAT written with `pack` (one file for both hooks, exact keys), and a version with port translation, so inside hosts that use the same source port no longer collide, are `dist/examples/flow/nat-pack.bpfc` and `nat-pat.bpfc`, explained in [doc/flow-tracking.md](doc/flow-tracking.md#81-nat-three-ways).

NAT ICMP traffic on eth0
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

NAT TCP traffic on eth0
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

NAT UDP traffic on eth0
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

### 5. IP Fragmentation and Reassembly

Split oversized IPv4 packets into several packets of a maximum size, even those with the DF bit set. Optionally reassemble the fragments into the original packet, for cases where the application doesn't support reassembly.

```bash
#Fragment packets of up to 9000 bytes into 1400-byte fragments when received on eth0
bpfc -i eth0 -d ingress -p 100 "ip-frag 1400 9000;"

#Reassemble fragmented packets when sending to eth0
bpfc -i eth0 -d egress -p 100 "ip-defrag"
```

Note: the `ip-frag <size> <max>` and `ip-defrag` commands add the match for IPv4 packets by themselves, but ignore the DF bit by design. To leave packets with the DF bit set unfragmented, put `match ip-ndf` before `ip-frag`, so it only matches packets without the DF bit.

The largest reassembled packet `ip-defrag` can make is the interface MTU. When forwarding, attach `ip-frag` to ingress and `ip-defrag` to egress. On an end host, do the opposite: `ip-frag` on egress and `ip-defrag` on ingress.

The examples below use the [preprocessor](#compile-time-preprocessor) (`const`, `define`, `include`, `repeat`, `when`, `$IFNAME`/`$IFINDEX`/`$IFMAC`/`$HOOK`) for common network problems: 6–12 are XDP programs (the earliest hook, for forwarding and filtering at line rate), 13–18 TC programs (both directions, and the kernel's skb metadata: marks for policy routing, departure times for pacing, clones for mirroring). They are installed in `/usr/share/doc/bpfc/examples/{xdp,tc}/` (`dist/examples/` in the source), and `tests/test-xdp-examples.sh` and `tests/test-tc-examples.sh` run each of them as it is. Attach one with `bpfc -i <iface> -d xdp -f <file>` (or `-d ingress|egress -p <prio>`), or let bpfcd do it: copy it to `/etc/bpfc/interfaces.d/<iface>/xdp.bpfc` or `.../<iface>/{ingress,egress}/<prio>.bpfc` (or `%all%/`, `%nic%/`, ... for every interface; `$IFNAME`, `$IFINDEX` and `$IFMAC` are then each interface's own). Constants can be changed without editing the file: `-s MSS=1400`.

### 6. Fast-path IPv4 routing in XDP

The kernel stays the control plane (routes, neighbours, `ip rule`, FRR, ...), and XDP does the forwarding: the destination is looked up in the kernel's FIB, TTL is decremented with an incremental checksum update, and the packet is redirected to the next hop's MAC and interface, before an skb is allocated, before GRO, netfilter and the stack. Whatever the program does not forward continues to the kernel, which handles it as before: a TTL about to expire (ICMP time exceeded), no route, a neighbour that is not resolved yet (the kernel resolves it; the next packets take the fast path), local destinations, ARP, IPv6, and IPv4 with a FIB result other than success.

`ip-lib.bpfc`, a small macro library:
```
# ip-lib.bpfc: macros shared by the XDP examples (include ip-lib.bpfc;).

# dec-ttl: IPv4 TTL - 1, with the header checksum updated incrementally
# (RFC 1141: the checksum goes up by 0x0100, with the end-around carry).
# get bytes gives host order; set bytes %VAR writes the variable as it is,
# so the checksum is turned back to network order first.
define dec-ttl;
  decl TTL_$UNIQUE 1; decl CK_$UNIQUE 4; decl CY_$UNIQUE 4;
  get bytes 22 1 TTL_$UNIQUE; calc sub TTL_$UNIQUE 1; set bytes 22 1 %TTL_$UNIQUE;
  get bytes 24 2 CK_$UNIQUE; calc add CK_$UNIQUE 0x100;
  set val CY_$UNIQUE %CK_$UNIQUE; calc rsh CY_$UNIQUE 16;
  calc and CK_$UNIQUE 0xffff; calc add CK_$UNIQUE %CY_$UNIQUE;
  calc hton CK_$UNIQUE 16; set bytes 24 2 %CK_$UNIQUE;
end-define;
```

`router.bpfc`:
```
# router.bpfc: IPv4 forwarding in XDP. The kernel's routing table decides
# (fib-lookup); the program forwards what it can and passes everything else
# (TTL about to expire, no route, unresolved neighbour, local traffic, ARP,
# IPv6, ...) to the kernel, which handles it as usual.
#   bpfc -i eth0 -d xdp -f router.bpfc            (one per interface, or bpfcd %nic%/xdp.bpfc)
#   -s FLOW=1: hash multipath routes per flow (protocol and ports), for
#              net.ipv4.fib_multipath_hash_policy=1
include ip-lib.bpfc;
const FLOW 0;
match ip;
  decl TTL 1; get bytes 22 1 TTL;
  match val %TTL gt 1;
    decl DST 4; get ip-dst DST;
    when FLOW;
      fib-lookup flow %DST;
    otherwise;
      fib-lookup %DST;
    end-when;
    match val %FIB_RESULT eq 0;
      dec-ttl;
      set dst-mac %FIB_DMAC; set src-mac %FIB_SMAC;
      redirect %FIB_IFINDEX;
    end-match;
  end-match;
end-match;
```

```bash
sysctl -w net.ipv4.ip_forward=1          # the FIB helper needs forwarding on
for i in eth0 eth1 eth2; do bpfc -i $i -d xdp -f router.bpfc; done
```

Attach it to every interface a routed packet can arrive on. Netfilter does not see the fast-path packets: put filtering in front of it (see 8 and 12) or keep `match` blocks that `continue` the traffic the kernel must see. In generic mode XDP runs on any device; the native mode, when it comes, will skip the skb allocation altogether.

#### Multipath (ECMP) routes

With several next hops for a subnet the kernel's own selection applies, so nothing changes in the program:

```bash
ip route add 10.9.9.0/24 nexthop via 10.2.0.2 dev eth1 nexthop via 10.3.0.2 dev eth2
# or nexthop objects: weights, and resilient groups (a removed next hop moves only its own flows)
ip nexthop add id 1 via 10.2.0.2 dev eth1
ip nexthop add id 2 via 10.3.0.2 dev eth2
ip nexthop add id 10 group 1/2,3                                   # 1:3
ip nexthop add id 11 group 1/2 type resilient buckets 64
ip route add 10.9.9.0/24 nhid 11
```

`bpf_fib_lookup` hashes the fields the program gives it. With the default `net.ipv4.fib_multipath_hash_policy=0` that is the source and destination addresses, which `fib-lookup` always fills in: flows spread per host pair. With policy 1 (5-tuple) the protocol and ports are needed too, or every flow between two hosts takes the same path: compile with `-s FLOW=1` (`fib-lookup flow %DST`). Then the program picks the same next hop as the kernel would for the same flow, so a flow does not change path when some of its packets go through the kernel (a neighbour miss, say). Fragments are hashed without ports, so all fragments of a datagram take the same path. A next hop whose link goes down is dropped from the selection as for the kernel (`net.ipv4.conf.*.ignore_routes_with_linkdown=1` to drop it on carrier loss).

To spread by something the kernel does not hash on (a weight per tenant, a map of pinned flows), choose the next hop in the program and look it up instead of the destination: `fib-lookup 10.2.0.2` gives that next hop's MAC and interface, as in the pseudowire example (3).

### 7. TCP MSS clamping

Tunnels, PPPoE and IPsec lower the path MTU; when ICMP "fragmentation needed" is filtered somewhere, TCP connections hang once they send full-size segments. Clamping the MSS in the SYNs makes both ends send segments that fit. The program walks the TCP options with an unrolled `repeat` (`break-repeat`, `next-repeat`), so it finds the MSS wherever it is, lowers it only when it is larger, and recomputes the checksum once.

```
# mss-clamp.bpfc: lower the MSS of TCP SYNs to $MSS (-s MSS=...), for links
# with a smaller MTU (tunnels, PPPoE, IPsec). Walks the TCP options, at most
# 10, so it finds the MSS wherever it is; recomputes the TCP checksum once.
const MSS 1360;
match tcp; match tcp-flags SYN;
  decl VI 1; get bytes 14 1 VI;
  match val %VI eq 0x45;                                        # IPv4 without IP options
  decl O 2; decl E 2; decl K 1; decl L 1; decl M 2; decl CH 1;
  set val O 54;                                                 # first option (14 + 20 + 20)
  get bytes 46 1 E; calc rsh E 4; calc mul E 4; calc add E 34;  # end of the TCP header
  repeat 10;
    if O ge %E; break-repeat; end-if;
    get bytes %O 1 K;
    if K eq 0; break-repeat; end-if;                            # end of options
    if K eq 1; calc add O 1; next-repeat; end-if;               # NOP
    if K eq 2;                                                  # MSS: kind 2, length 4
      calc add O 2; get bytes %O 2 M;
      if M gt $MSS; set val M $MSS; calc hton M 16; set bytes %O 2 %M; set val CH 1; end-if;
      break-repeat;
    end-if;
    calc add O 1; get bytes %O 1 L; calc add O %L; calc sub O 1;   # other option: skip its length
  end-repeat;
  if CH eq 1; recalc-tcp-csum; end-if;
end-match; end-match; end-match;
```

```bash
bpfc -i ppp0 -d xdp -s MSS=1452 -f mss-clamp.bpfc        # 1492 - 40
```

Attach it to the interface the SYNs arrive on, in both directions' ingress (the SYN and the SYN-ACK). Packets with IP options are left alone (the first byte of the IP header must be 0x45). (TC egress works too: `-d egress`, for traffic the host itself sends.)

### 8. Source address validation (uRPF, BCP 38)

Drop packets whose source the network would not route back to: spoofed sources, bogons, our own addresses arriving from outside. Strict mode also requires the route back to use the interface the packet came in on; loose mode (`-s LOOSE=1`) only requires that a route exists, for asymmetric routing. One file covers every interface through `$IFINDEX`:

```
# urpf.bpfc: source address validation (BCP 38, RFC 3704) on every interface
# (bpfcd: interfaces.d/%all%/xdp.bpfc). Drops a packet when the routing table
# has no way back to its source; strict mode also drops it when the way back
# is not the interface it came in on (asymmetric routing: use -s LOOSE=1).
# The kernel's FIB helper needs forwarding enabled on the interface.
const LOOSE 0;
match ip;
  decl SRC 4; get ip-src SRC;
  if SRC ne 0;                                       # 0.0.0.0 (DHCP) is not checked
    fib-lookup %SRC;
    if FIB_RESULT ge 1; if FIB_RESULT le 4; drop; end-if; end-if;   # blackhole, unreachable, prohibit, our own address
    when !LOOSE;
      if FIB_RESULT eq 0; if FIB_IFINDEX ne $IFINDEX; drop; end-if; end-if;
      if FIB_RESULT eq 7; if FIB_IFINDEX ne $IFINDEX; drop; end-if; end-if;   # route found, neighbour not resolved yet
    end-when;
  end-if;
end-match;
```

```bash
cp urpf.bpfc /etc/bpfc/interfaces.d/%nic%/xdp.bpfc && systemctl reload bpfcd
```

XDP has one program per interface, so to combine this with the router (6), put both in one file: `include` this one before the router's commands. (A `drop` ends the program; what passes goes on to the routing part.)

### 9. Direct-server-return load balancer

A layer-4 load balancer for a TCP service on a virtual IP, as Katran or Maglev do it: each flow (source address and port) is sent to one backend by rewriting only the destination MAC, so there is no checksum work and no connection state, and the backends answer the client directly. The backends are on the same layer-2 segment and have the VIP on their loopback (`ip addr add 10.9.0.100/32 dev lo`, with `arp_ignore=1`, `arp_announce=2`). `$IFMAC` is the load balancer's own MAC, and each `backend` line is a `define` used once per server:

```
# dsr-lb.bpfc: direct-server-return load balancer for a TCP service on a VIP.
# Each flow (source address and port) goes to one backend; only the
# destination MAC changes, so no checksum work. The backends have the VIP on
# their loopback and answer the client directly. Add a backend line per server.
const VIP 10.9.0.100;
const PORT 80;
const BACKENDS 3;
define backend N MAC;
  if B eq $N; set dst-mac $MAC; set src-mac $IFMAC; tx; end-if;
end-define;
match tcp; match ip-dst $VIP; match tcp-dst $PORT;
  decl B 4; decl P 4;
  get ip-src B; get tcp-src P; calc xor B %P; calc mod B $BACKENDS;
  backend 0 02:00:00:00:00:a0;
  backend 1 02:00:00:00:00:a1;
  backend 2 02:00:00:00:00:a2;
end-match; end-match; end-match;
```

Changing the number of backends moves most flows; for long-lived connections, use a consistent hash (a Maglev-style table in a map, indexed by the flow hash) instead of the modulo.

### 10. VLAN translation on a trunk

Map customer VLANs onto provider VLANs (or back) where two networks meet. The `repeat` unrolls into one `match vlan-id` per VLAN, so the mapping is a few constants; `set vlan-id` keeps each tag's priority:

```
# vlan-translate.bpfc: map customer VLANs $FROM..$FROM+$COUNT-1 to provider
# VLANs from $TO on a trunk. The repeat unrolls into one match per VLAN; the
# tag's priority bits stay.
const FROM 100;
const TO 2000;
const COUNT 10;
repeat $COUNT as I;
  match vlan-id $(FROM + I); set vlan-id $(TO + I); break-repeat; end-match;
end-repeat;
```

```bash
bpfc -i eth1 -d xdp -s FROM=100 -s TO=2000 -s COUNT=50 -f vlan-translate.bpfc
```

### 11. Packet-size histograms on every interface

Cheap traffic profiling: count packets per size bucket on every interface, with a map named after it. In bpfcd's `%all%/xdp.bpfc`, each interface gets its own `SIZES_<name>` map:

```
# size-histogram.bpfc: packet sizes per interface (bpfcd %all%), in buckets
# up to 64, 128, ..., 8192 bytes: map SIZES_<interface>, key = bucket.
#   bpfc -m <dir> -r SIZES_eth0
decl LEN 4; get len LEN;
repeat 8 as I;
  if LEN le $(64 << I); calc-map add SIZES_$IFNAME $I 1; break-repeat; end-if;
end-repeat;
```

```bash
bpfc -m /sys/fs/bpf -r SIZES_eth0          # key = bucket: 0 for <= 64 bytes, 1 for <= 128, ...
```

### 12. SYN-flood guard

Limit each source to `$LIMIT` TCP SYNs per window of about a second, and drop the rest before they reach the TCP stack. The counters are in an LRU hash keyed by window number and source, so old windows age out without cleanup:

```
# syn-guard.bpfc: at most $LIMIT TCP SYNs per source address per window of
# 2^30 ns (about a second); the rest are dropped. Counters live in an LRU hash
# keyed by window and source, so old windows age out by themselves.
const LIMIT 100;
match tcp; match tcp-flags SYN;
  decl K 8; decl S 4; decl OLD 8;
  get time K; calc rsh K 30; calc lsh K 32;        # window number in the high half
  get ip-src S; calc or K %S;
  calc-map add SYNS %K 1 OLD;
  if OLD ge $LIMIT; drop; end-if;
end-match; end-match;
```

```bash
bpfc -i eth0 -d xdp -s LIMIT=50 -f syn-guard.bpfc
```

Legitimate clients behind one NAT share a source address, so set the limit for the busiest of them; SYN cookies (`net.ipv4.tcp_syncookies`) remain the kernel's defence against a flood from many sources.

### 13. Application-based policy routing (two uplinks)

Send some applications out of a second uplink (a cheaper link, a low-latency one, a VPN) while everything else keeps the default route, as an SD-WAN edge does. The TC ingress program on the LAN interface runs before the routing decision and only marks the packets; `ip rule` picks the table for the mark. Each `app` line is one use of a `define`:

```
# app-routing.bpfc: send some applications out of a second uplink (TC ingress,
# on the LAN interface, before the routing decision). The program only marks
# the packets; ip rule picks the routing table for the mark:
#   ip rule add fwmark 2 table 200
#   ip route add default via <second uplink's gateway> table 200
const MARK 2;
define app PROTO PORTS;
  match $PROTO; match $PROTO-dst $PORTS; set skb-mark $MARK; end-match; end-match;
end-define;
app udp 5060;            # SIP
app udp 10000-20000;     # RTP
app tcp 3389;            # remote desktop
```

```bash
ip rule add fwmark 2 table 200
ip route add default via 192.0.2.1 dev wan2 table 200
bpfc -i lan0 -d ingress -p 10 -f app-routing.bpfc
```

The kernel still forwards, so netfilter, NAT and conntrack apply as usual (with conntrack, `CONNMARK` can keep the mark for the replies). It steers forwarded traffic: the router's own packets are routed before TC egress sees them, so a mark set there comes too late; mark those with the socket (`SO_MARK`) or netfilter's `OUTPUT` chain instead.

### 14. DSCP classification for QoS

Mark traffic by application so that the queues along the path (the local qdisc, the WAN routers) can prioritise it: voice as EF, conferencing media as AF41, bulk transfers as CS1, below best effort. The IP checksum is updated with the DSCP. The first matching `class` wins (`continue` ends the program):

```
# dscp-classify.bpfc: mark traffic for QoS by application (TC egress, on the
# WAN interface or on a host). The DSCP goes in the IP header (the checksum
# is updated), so routers along the path and the local qdisc can queue by it.
const EF 0xb8;           # DSCP 46: voice
const AF41 0x88;         # DSCP 34: interactive video
const CS1 0x20;          # DSCP 8: bulk, below best effort
define class PROTO PORTS TOS;
  match $PROTO; match $PROTO-dst $PORTS; set ip-tos $TOS; continue; end-match; end-match;
end-define;
class udp 5060 $EF;
class udp 10000-20000 $EF;
class udp 3478-3497 $AF41;     # STUN/TURN media (conferencing)
class tcp 873 $CS1;            # rsync
class tcp 20-21 $CS1;          # ftp
```

```bash
bpfc -i wan0 -d egress -p 10 -f dscp-classify.bpfc
```

On egress it also marks what the host itself sends; on a router, attach it to the LAN interface's ingress to mark before forwarding. A qdisc that queues by DSCP (`cake diffserv4`, or `prio`/`htb` with `tc filter` on the TOS) then does the scheduling.

### 15. Sampled port mirroring

Send a copy of one packet in `$RATE` to an IDS or a capture host, without slowing the traffic itself. `clone` exists only in TC (XDP cannot copy a packet):

```
# sampled-mirror.bpfc: copy one packet in $RATE to a monitoring interface (an
# IDS, a capture host) without slowing the traffic itself (TC ingress or
# egress; clone exists only in TC). Restrict it with a match to sample a
# subnet or a service.
const RATE 100;
const MIRROR mon0;
decl R 4; get random R; calc mod R $RATE;
if R eq 0; clone $MIRROR egress; end-if;
```

```bash
bpfc -i eth0 -d ingress -p 5 -s RATE=1000 -s MIRROR=mon0 -f sampled-mirror.bpfc
```

Put a `match` around it to sample one subnet or service, and attach it to both directions to see both halves of the flows.

### 16. Token-bucket policer

Limit traffic from a subnet (a guest network, a customer) to a rate, with a burst allowance, and drop the excess. The bucket holds wire time in nanoseconds rather than bytes, so each packet costs a multiplication and there is no rounding: at high packet rates a bucket in bytes, earning `elapsed * rate` per packet, would round every packet's share down to nothing.

```
# policer.bpfc: a token-bucket policer: traffic from $NET gets $RATE bit/s
# with bursts of $BURST bytes, and the excess is dropped (TC ingress or
# egress). The bucket holds wire time in ns, so there is no division per
# packet: it fills with the time that passes and each packet costs its
# length times $NS_PER_BYTE. Map POLICE: 0 = time of the last packet,
# 1 = credit in ns. It is shared by all CPUs without locking (approximate).
# TCP backs off on the drops; to delay instead of drop, see edt-pacing.bpfc.
const NET 10.1.0.0/24;
const RATE 8000000;                          # bit/s (up to 8 Gbit/s: whole ns per byte)
const BURST 30000;                           # bytes
const NS_PER_BYTE $(8000000000 / RATE);
match ip; match ip-src $NET;
  decl NOW 8; decl LAST 8; decl CREDIT 8; decl COST 8;
  get time NOW; get map POLICE 0 LAST; get map POLICE 1 CREDIT;
  calc add CREDIT %NOW; calc sub CREDIT %LAST;                   # + the time since the last packet
  if CREDIT gt $(BURST * NS_PER_BYTE); set val CREDIT $(BURST * NS_PER_BYTE); end-if;
  set map POLICE 0 %NOW;
  get len COST; calc mul COST $NS_PER_BYTE;
  if CREDIT lt %COST; set map POLICE 1 %CREDIT; drop; end-if;
  calc sub CREDIT %COST; set map POLICE 1 %CREDIT;
end-match; end-match;
```

```bash
bpfc -i lan0 -d ingress -p 10 -m /sys/fs/bpf -s NET=192.168.50.0/24 -s RATE=20000000 -f policer.bpfc
```

A policer drops, and TCP reacts to drops by backing off hard; for traffic the host sends, pacing (18) delays instead.

### 17. Per-host traffic accounting, both directions

Bytes per inside host, in each direction, on the WAN interface: one file attached to both hooks, telling them apart with `$HOOK` (when going out, the inside host is the source; coming in, the destination). The maps are `BYTES_egress` and `BYTES_ingress`, keyed by the IPv4 address in host order:

```
# host-accounting.bpfc: bytes per inside host, in both directions, on the
# WAN interface: attach the same file to ingress and egress. $HOOK tells the
# two apart: going out, the inside host is the source; coming in, the
# destination. Maps BYTES_egress and BYTES_ingress, key = the IPv4 address.
#   bpfc -m /sys/fs/bpf -r BYTES_egress
match ip;
  decl HOST 4; decl LEN 8;
  when $HOOK == egress;
    get ip-src HOST;
  otherwise;
    get ip-dst HOST;
  end-when;
  get len LEN;
  calc-map add BYTES_$HOOK %HOST %LEN;
end-match;
```

```bash
for h in ingress egress; do bpfc -i wan0 -d $h -p 20 -m /sys/fs/bpf -f host-accounting.bpfc; done
bpfc -m /sys/fs/bpf -r BYTES_egress           # key 0x...c0a83202 = 192.168.50.2
```

### 18. Rate limiting without drops: EDT pacing

Pace traffic to a destination (a backup target, a remote site with a small link) by giving each packet an earliest departure time. The `fq` qdisc holds each packet until then, so the traffic leaves at `$RATE` without drops, and TCP sees a clean bottleneck instead of losses. Packets that would wait more than `$HORIZON` are dropped, to bound the queue:

```
# edt-pacing.bpfc: pace traffic to $NET at $RATE bit/s by giving each packet
# an earliest departure time (TC egress, with the fq qdisc on the interface:
# tc qdisc replace dev eth0 root fq). Packets are delayed, not dropped, so TCP
# sees a clean bottleneck. Map PACE key 0 is the next free departure time;
# packets more than $HORIZON ns ahead are dropped.
const NET 10.9.9.0/24;
const RATE 16000000;
const HORIZON 200000000;           # 200 ms of queue
match ip; match ip-dst $NET;
  decl NOW 8; decl NEXT 8; decl LEN 8; decl AHEAD 8;
  get time NOW; get map PACE 0 NEXT;
  if NEXT lt %NOW; set val NEXT %NOW; end-if;
  set val AHEAD %NEXT; calc sub AHEAD %NOW;
  if AHEAD gt $HORIZON; drop; end-if;
  set tstamp %NEXT;
  get len LEN; calc mul LEN $(8000000000 / RATE);              # ns this packet takes on the wire
  calc add NEXT %LEN; set map PACE 0 %NEXT;
end-match; end-match;
```

```bash
tc qdisc replace dev wan0 root fq
bpfc -i wan0 -d egress -p 10 -m /sys/fs/bpf -s NET=198.51.100.0/24 -s RATE=50000000 -f edt-pacing.bpfc
```

The departure times are CLOCK_MONOTONIC, as `get time` gives them. The next-departure time in map `PACE` is shared by all CPUs without locking, so the rate is approximate under heavy parallel load; one key per destination (a map keyed by `ip-dst`) paces each destination separately.

### 19. Flow tracking: NAT with port translation, load sharing, CoPP, accounting, sampling

`dist/examples/flow` (installed to the doc directory, `examples/flow`) has programs built on `hash`, `pack`, `count`, `seen`, `over-rate` and prefix maps: NAT with exact keys and with port translation (`nat-pack.bpfc`, `nat-pat.bpfc`), symmetric firewall load sharing (`fw-loadshare.bpfc`), control-plane policing (`copp.bpfc`), a SYN guard per /24, a policer and a two-colour marker in one line each (`syn-guard-subnet.bpfc`, `policer-rate.bpfc`, `tenant-marker.bpfc`), per-customer and per-conversation accounting with readable tables (`customer-accounting.bpfc`, `conversations.bpfc`), whole-flow sampling (`flow-sample.bpfc`), duplicate removal (`dedup-simple.bpfc`) and storm control (`storm-control.bpfc`). [doc/flow-tracking.md](doc/flow-tracking.md) explains each of them, and how to choose a key, for network engineers.

---

## Testing

```bash
make check-compile        # compile tests: no root, no network
sudo make check           # the main suites (root; creates namespaces and veth pairs)
sudo ./test.sh            # every suite (about an hour)
sudo ./test.sh nat xdp    # only these
```

[TESTING.md](TESTING.md) describes every suite, which ones need root, the tools each one needs, and coverage (`make coverage`) and fuzzing (`make fuzz`).

---

## Documentation

| Document | Covers |
| :--- | :--- |
| [INSTALL.md](INSTALL.md) | Requirements, building, `make install`, RPM, Debian, Alpine, Arch and OpenWrt packages, static builds, containers |
| [TESTING.md](TESTING.md) | The test suites, what they need, coverage and fuzzing |
| [doc/language.md](doc/language.md) | The complete language reference |
| [doc/flow-tracking.md](doc/flow-tracking.md) | Flow keys (`hash`, `pack`) for network engineers: NAT, load sharing, CoPP, policers, accounting, sampling |
| [doc/firewall.md](doc/firewall.md) | The Cisco IOS access-list frontend |
| [dist/container/README.md](dist/container/README.md) | Running bpfcd in a container |
| `programs/*/DESIGN.md`, [programs/dedup/README.md](programs/dedup/README.md) | The included programs |
| `bpfc(8)`, `bpfcd(8)`, `bpfcctl(8)`, `bpfc.conf(5)` | Man pages |

bpfc is licensed under the GNU General Public License v3 (see [LICENSE](LICENSE)).
