# bpfc language reference

This is the full reference for the bpfc language. The [README](../README.md#language-overview) has a shorter overview with examples, and `bpfc(8)` and `bpfc -h` list every command. [flow-tracking.md](flow-tracking.md) explains flow keys for network engineers, and [firewall.md](firewall.md) the Cisco IOS ACL frontend.

- [Program structure](#program-structure)
- [Variables](#variables)
- [Branching & Control Flow](#branching--control-flow)
- [Protocol Shorthands](#protocol-shorthands)
- [tcpdump-style Matches](#tcpdump-style-matches)
- [Packet Data Fields (`get`, `set`, `match`)](#packet-data-fields-get-set-match)
- [Context Metadata (`__sk_buff`)](#context-metadata-__sk_buff)
- [ALU Math Engine (`calc`)](#alu-math-engine-calc)
- [eBPF Maps (State Tracking)](#ebpf-maps-state-tracking)
- [Flow Keys (`hash`, `pack`) and Commands Built on Them](#flow-keys-hash-pack-and-commands-built-on-them)
- [Routing & Forwarding](#routing--forwarding)
- [Structural Manipulation & Checksums](#structural-manipulation--checksums)
- [Constants, Macros, Includes and Unrolled Loops](#constants-macros-includes-and-unrolled-loops)
- [Runtime loops and jumps](#runtime-loops-and-jumps)
- [Diagnostics and logging](#diagnostics-and-logging)

## Program structure

A program is a list of commands separated by semicolons. On the command line it is one quoted string; in a file (`-f`, or a file bpfcd manages) you can put one command per line, several per line, or both, and `#` starts a comment that runs to the end of the line. Indentation is free.

Variables (`%NAME` when read) live on the 512-byte eBPF stack. They hold values in host byte order, so `calc` works on them directly, and `get`/`set`/`match` convert to and from the packet's network order.

A `match` (or `if`) opens a block, and `end-match` (or `end-if`) closes it. Commands inside run only when the condition holds; blocks nest. When the program reaches its end, the packet goes on to the next filter, as if by `continue`.

## Variables
* `decl <VAR> <size>` - Create a new variable of `<size>` bytes (1, 2, 4, 8 or 16). A 16-byte variable holds an IPv6 address in network byte order, for `get`, `set` and `match` of `ip6-src`/`ip6-dst`.
* `set val <VAR> <%VAR | int>` - Set variable to integer value or value from another variable
* `free <VAR>` - Free `VAR` from the stack, making space available for later variables.

**Stack layout.** The 512-byte stack holds 128 bytes of fixed scratch used inside single instructions, then one 8-byte slot per variable (two for a 16-byte one), as many as the program declares, up to 48 slots. Instructions that need more scratch (`fib-lookup`: 72 bytes, `push-eth`: 32, the byte-insertion and deletion commands) take it below the variables and give it back when they finish. `xor-packet` and the TCP/UDP checksums stage packet data in chunks of up to 256 bytes: with more than 16 variables the chunks get smaller (down to 8 and 4 bytes), which works the same but costs more verifier instructions. The variables `fib-lookup` adds (`FIB_RESULT`, `FIB_SMAC`, `FIB_DMAC`, `FIB_IP_DST`, `FIB_IFINDEX`) count as five. If something does not fit, bpfc says which instruction needs how much; `free` variables you no longer need.

## Branching & Control Flow
* `match|if <field> <value>` - Opens a conditional block. If the packet field does not match the value, execution jumps past the block.
* `match|if val %VAR <op> <val | %VAR>`, or the short form `if <VAR> <op> <val | %VAR>` - Compares variables logically (`lt`, `gt`, `le`, `ge`, `eq`, `ne`). `seq-lt`, `seq-le`, `seq-gt`, `seq-ge` compare 32-bit wrapping counters such as TCP sequence numbers (serial-number order, RFC 1982: A is before B when `(int32)(A - B) < 0`), valid while the two are less than 2^31 apart.
* `else` - Inverse of match/if criteria.
* `end-match|end-if` - Closes the most recent conditional `match` block.

**Terminal commands** end the program for this packet. Each must be the last command of the program, or be followed by `end-match`, `end-if` or `else`.

* `continue` - Pass the packet on: TC evaluates the next filter (the next priority). A program that reaches its end without a terminal command does the same.
* `accept` - Accept the packet without running the filters after this one.
* `drop` - Silently drop the packet.
* `reclassify` - Restart TC evaluation from the first filter.
* `redirect`, `redirect-neigh` - Send the packet out of another interface (see [Routing & Forwarding](#routing--forwarding)).
* `tx` - XDP only: send the packet back out of the interface it arrived on.

In XDP programs `accept` and `continue` both pass the packet on (XDP_PASS); see the README's [XDP](../README.md#tc-and-xdp-hooks) section.

## Protocol Shorthands
Quick boolean filters for specific L2/L3 types. Use as standalone matches (e.g., `match tcp;`).
* Supported: `ip`, `ip6`, `arp`, `icmp`, `gre`, `tcp`, `udp`, `igmp`, `ospf`, `pim`, `esp`, `rsvp`, `l2tp`, `vlan`, `qinq`.

## tcpdump-style Matches
* `match host <addr | %VAR>` / `match net <prefix>` - IPv4 source or destination.
* `match port <n | lo-hi | %VAR>` - TCP, UDP or SCTP source or destination port (IPv4, not later fragments); `match src-port ...`, `match dst-port ...` one side.
* `match dscp <name | 0-63>`, `match ecn <not-ect | ect1 | ect0 | ce | 0-3>` - IPv4. DSCP names: `default`/`be`/`cs0`, `le`, `cs1`-`cs7`, `af11`-`af43`, `va`, `ef`; `set dscp` / `set ecn` take them too.

## Packet Data Fields (`get`, `set`, `match`)
Fields support extraction (`get <field> <VAR>`), assignment (`set <field> <val | %VAR>`), and evaluation (`match <field> <val | %VAR>`). Subnets (`10.0.0.0/24`) and port ranges (`80-100`) are fully supported. Numbers may be decimal or `0x` hex anywhere. Values are checked when compiling: a number must fit the field (port 0-65535, `ip-tos` 0-255, `vlan-id` 0-4095, ...), addresses must be complete (`10.0.0.300`, `10.0.0` or a 5-byte MAC are errors), and a range must be low-high; `redirect`/`clone` to an interface that does not exist is an error too. Variables hold host-order values, so `match <field> %VAR` compares with what `get <field>` stored (for `mpls-label`, the label itself). `match vlan` / `match qinq` look at the offloaded tag, or at the frame when no tag is offloaded.

* **L2:** `dst-mac`, `src-mac`, `eth-proto`, `vlan-id` (`set vlan-id` replaces the id of the tag and keeps its priority and TPID; without a tag it adds an 802.1Q one)
* **IPv4:** `ip-src`, `ip-dst`, `ip-tos`, `ip-proto` (`set ip-src`/`ip-dst` update the IP checksum and the TCP/UDP checksum, whose pseudo-header covers the addresses; a UDP checksum of 0 stays 0)
* **IPv6:** `ip6-src`, `ip6-dst`, `ip6-tclass`, `ip6-flow`, `ip6-proto`
* **L4:** `tcp-src`, `tcp-dst`, `udp-src`, `udp-dst`, and `match tcp-flags <flag>...` (all of FIN, SYN, RST, PSH, ACK, URG given must be set; any case; an unknown flag is an error), `icmp-type`. These follow the real IPv4 header length (IHL), so packets with IP options are read and rewritten at the right place (they used to be read at fixed offsets that assume a 20-byte header). They are IPv4 fields: on another packet a match does not match, `get` stores 0 and `set` changes nothing.
* **ARP:** `arp-htype`, `arp-ptype`, `arp-hlen`, `arp-plen`, `arp-oper`, `arp-sha`, `arp-tha`, `arp-spa`, `arp-tpa`
* **MPLS:** `mpls-label`, `mpls-bos`
* **GRE:** `gre-key`, `gre-proto` (any IHL; the key is found after the checksum when the C bit is set)
* **TCP (IPv4, any IHL; `get` only):** `tcp-seq`, `tcp-ack`, `tcp-flags` (the flags byte: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10), `tcp-win` (unscaled), `tcp-hlen` (header length incl. options, bytes). 0 when the packet is not IPv4 TCP.
* **Offsets and lengths (IPv4, any IHL; `get` only):** `l4-off` (offset of the TCP/UDP/... header in the frame), `payload-off` (TCP: after the options, UDP: after 8 bytes), `payload-len` (from the IP total length, so Ethernet padding is not counted). Use them with variable offsets: `get bytes %OFF 4 V`.
* **Flow key (`get` only):** `flow-key [reverse | symmetric]` - the same as `hash VAR 64 [reverse | symmetric] ip-src ip-dst ip-proto src-port dst-port` (below): a 64-bit hash of the IPv4 addresses, protocol and TCP/UDP/SCTP ports (never 0; 0 for non-IPv4; ports 0 for fragments). `reverse` is the key of the opposite direction, so a returning ACK finds its data flow's map entry; `symmetric` is the same key for both directions. (Its values changed when `hash` was added: maps keyed by it start new entries after an upgrade.)
* **Any-protocol fields (`get`, `set` ports):** `src-port`, `dst-port` (TCP, UDP or SCTP; 0 for other protocols and fragments; `set` rewrites TCP or UDP with the checksum), `dscp`, `ecn` (`set` keeps the other bits of the TOS byte; names above), `ip-ttl`, `icmp-type`, `icmp-code`, `icmp-id` (`get` only; `icmp-id` for echo requests and replies), `l4-proto` (`get` only: the transport protocol, for IPv6 after the extension headers) and `frag-off` (`get` only: the fragment offset, 0 when the packet is not a later fragment).
* **Generic:** `bytes <offset | %VAR> <length>` - with a variable offset the bytes are read with `bpf_skb_load_bytes` (0 if outside the packet) and written with `bpf_skb_store_bytes` (nothing written if outside).

## Context Metadata (`__sk_buff`)
* `len` - Packet length (`u32`).
* `protocol` - Protocol stored in sk_buff, as an EtherType (`match protocol 0x0800`; `get` stores it in host order).
* `skb-ifindex` - Interface number associated with sk_buff.
* `dev-type` (get/match), `dev-kind` (match) - The device type (`skb->dev->type`, ARPHRD: 1 Ethernet, 772 loopback, 778 GRE, 768 IPIP, 65534 none, e.g. wireguard and tun) and kind (`veth`, `gre`, `vxlan`, ...; `nic` without a kind, `lo`) of the `-i` interface. They are looked up when compiling (TC programs cannot read `skb->dev`), so a match costs no instructions: it is always true, or its block is never entered. Without `-i`, pass `-s IFTYPE=<n> -s IFKIND=<kind>`.
* `skb-ingress` - Ingress interface number associated with sk_buff.
* `skb-mark` - Netfilter/iptables firewall mark (`u32`).
* `skb-hash` - RPS flow hash (`u32`).
* `skb-priority` - `skb->priority`: the prio/pfifo_fast band, or an HTB class (major:minor as `0xMMMMmmmm`) the packet is queued in (`u32`).
* `gso-segs` - (`get`/`match` only) the number of segments a GSO/GRO packet is made of (`skb->gso_segs`); 0 or 1 for an ordinary packet.
* `tstamp` - `skb->tstamp`, 64-bit ns. On egress, a time in the future (CLOCK_MONOTONIC, as `get time`) holds the packet until then under the fq qdisc (earliest-departure-time pacing).
* `skb-cb <0-4>` - 20-byte control buffer array (5x `u32` slots) for passing state across tail-calls and to the next TC priority.
* `cpu` - (`get` only) number of the CPU running the program.
* `time` - (`get` only) CLOCK_MONOTONIC in ns (`bpf_ktime_get_ns`), into an 8-byte variable.
* `random` - (`get` only) a pseudo-random 32-bit number (`bpf_get_prandom_u32`).
* `queue` - Hardware TX queue mapping.

## ALU Math Engine (`calc`)
Performs mathematically-safe eBPF operations on standard 32/64-bit variables.
* `calc <op> <DST_VAR> <val | %SRC_VAR>`
* Operators: `add`, `sub`, `mul`, `div`, `or`, `and`, `lsh`, `rsh`, `mod`, `xor`
* `calc not <VAR>` - Unary bitwise inversion.
* `calc bswap <VAR> <bits>` - Flips byte order (16, 32, or 64 bits).
* `calc hton <VAR> [bits]` / `calc ntoh <VAR> [bits]` - Host/network byte order. `get bytes` returns host order; `set bytes` with a variable writes it as stored, so convert first.

## eBPF Maps (State Tracking)
Allows persistent data storage across packets and network interfaces.
* `get map <MAP_NAME> <key | %VAR> <VAL_DST_VAR>` - Loads value into variable (defaults 0 if missing).
* `set map <MAP_NAME> <key | %VAR> <val | %VAR>` - Updates or creates a 64-bit map entry.
* `save-packet <MAP_NAME> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Save packet data of specified length into a per-CPU map.
* `save-packet-keyed <MAP_NAME> <key | %VAR> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Save packet data of specified length into a global map into key number specified, allowing for storing packet contents for later recovery.
* `load-packet <MAP_NAME> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Load data of specified length from per-CPU map into packet.
* `load-packet-keyed <MAP_NAME> <key | %VAR> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Load data of specified length from keyed map into packet.
* `buffer-map <MAP_NAME> [size]` / `shared-buffer-map <MAP_NAME> [entries [size]]` - Declare a buffer map with smaller values (default 18000 bytes, 10000 shared entries) before using it. A copy at a constant offset may fill the rest of the entry; with a variable offset, offset and length are each capped at size/2. A pinned map of other sizes is replaced.
* Map names are pinned as `<map_dir>/<MAP_NAME>`: 1-31 characters, no `/`. The kernel keeps the last 15 characters of `[A-Za-z0-9_.]` as the map's own name (other characters become `_`), so names of 15 such characters or fewer show unchanged in `bpftool`.
* `array-map <MAP_NAME> <entries>` - Declare an array of 64-bit values (keys 0..entries-1) instead of the default 10000-entry LRU hash map: never evicts, all entries start at 0. Works with `get map`, `set map`, `calc-map`, `-r` and `-w`. A pinned map of another size is replaced.
* `hash-map <MAP_NAME> <entries>` - Declare the default LRU hash map with `entries` (1-16777216) instead of 10000. Comes before the map's first use; a pinned map of another size is replaced. Programs that use the map without declaring it take it as pinned.
* `tcp-option <kind | %VAR> <OFF_VAR> [LEN_VAR]` - Walks the TCP options (IPv4, any IHL) and sets `OFF_VAR` to the frame offset of the first option of that kind and `LEN_VAR` to its length byte; both 0 if there is none. Read or change the option with `get bytes` / `set bytes` / `fill-bytes` at `%OFF_VAR`.
* `fill-bytes <offset | %VAR> <len | %VAR> <byte | %VAR>` - Overwrite 1-64 packet bytes with one value (e.g. 1 to turn TCP options into NOPs). Nothing is written when the length is 0 or over 64, or the range is outside the packet. Checksums are not updated: on egress, locally sent TCP/UDP still has its checksum completed after the program (over the bytes as rewritten), so leave it; for forwarded or received packets follow with `recalc-tcp-csum`.
* `calc-map <add|or|and|xor|xchg> <MAP_NAME> <key | %VAR> <val | %VAR> [OLD_VAR]` - Atomic update of a 64-bit map value (created as 0); `OLD_VAR` receives the previous value. Safe when several CPUs update the same key, unlike `get map` + `set map`.
* `xor-packet <MAP_NAME> <len> [src [dst]]` / `xor-packet-keyed <MAP_NAME> <key> <len> [src [dst]]` - XOR packet bytes into a buffer (atomically; dst is a multiple of 8). Building block for XOR parity / FEC.
* `zero-buffer <MAP_NAME> <len> [dst]` / `zero-buffer-keyed <MAP_NAME> <key> <len> [dst]` - Zero part of a buffer.

## Flow Keys (`hash`, `pack`) and Commands Built on Them
A key picks a map entry: per host, per flow, per conversation. [flow-tracking.md](flow-tracking.md) explains them for network engineers, with examples (NAT, load sharing, CoPP, policers, accounting, sampling, duplicate removal).
* `pack <VAR> [symmetric|reverse] <field>[:bits] ...` - The fields side by side, the first in the highest bits: `pack K ip-src ip-dst` is `src << 32 | dst`. Exact and readable (`bpfc -r -K`), at most 64 bits. Fields have their natural width (address 32, port 16, VLAN 12, MAC 48, DSCP 6, ...); `ip-src/24` keeps the network bits (24), `:bits` the low bits, `%VAR[:bits]` a variable, `<n>:<bits>` a constant, `bytes <offset|%VAR> <1-8>` packet bytes, any other `get` field its value.
* `hash <VAR> <bits | buckets N> [symmetric|reverse] [seed <n|%VAR>] <field> ...` - Any fields, IPv6 addresses (`ip6-src`, `ip6-dst`, `ip6-src/64`) included, mixed into 1-64 bits (MurmurHash3's finaliser over 64-bit words), or `buckets N` = 0..N-1 spread evenly. The same in user space: `bpfc -H`. 64 bits: never 0 for a packet that has the fields.
* Keys of IPv4 (or IPv6) fields are 0 for other packets; ports are 0 for protocols without them and for every fragment. `reverse` swaps each source/destination pair (the reply's key); `symmetric` orders the pairs, the lower first, with one decision for all (both directions one key). Neither depends on the hook.
* `unpack <%SRC> <VAR>:<bits> ...` - A packed value taken apart, the first variable from the highest bits.
* `count <MAP> [<BYTES_MAP>] <key...>` - Atomically add 1 (and the frame length to the second map) to the key's entry. A key is a list of fields (packed when they fit in 64 bits, hashed otherwise), or one `%VAR`.
* `match seen <MAP> <key...> within <time> [refresh]` - True when the key was seen less than `<time>` (`50ms`, `2s`) ago; every packet records itself, atomically (of two copies at once exactly one is seen). The window runs from the first sighting, or with `refresh` from the last.
* `match over-rate <MAP> <key...> <rate> [burst <size>]` - True for packets above the rate per key: `100/s` (burst in packets) or `10mbit` (bit/s, burst in bytes, `64k` = 64 KiB); the burst defaults to 100 ms of the rate. A lock-free GCRA policer.
* `prefix-map <MAP> [entries] [ipv6] [static]` / `match <ip-src|ip-dst|%VAR> in <MAP> [VALUE_VAR]` - A longest-prefix-match table of IPv4 (with `ipv6`: IPv6) prefixes, filled with `bpfc -w MAP 10.0.0.0/8 1` (`-x` to remove). `VALUE_VAR` gets the longest match's value.
* `prefix <MAP> <prefix> [value]` - An entry (value default 1) of a `static` prefix map. A static map holds exactly the program's `prefix` lines: they are written when the program is attached, and entries the program no longer lists are deleted.
* `transport <PROTO> <SPORT> <DPORT> <TCPFLAGS> <ICMPTYPE> <ICMPCODE> <FRAGOFF>` - Read the transport header once into seven variables (`-` skips one): the protocol (IPv6: after up to four extension headers, fragment headers included), the TCP/UDP/SCTP ports, the TCP flags, the ICMP or ICMPv6 type and code, and the fragment offset. Ports, flags and ICMP fields are 0 in a later fragment. Rules that then compare variables cost a few instructions each; the `acl` frontend is built on this.

## Routing & Forwarding
* `fib-lookup [options] [<address> | %VAR]` - Queries the kernel's routing tables (`bpf_fib_lookup`, IPv4), for the packet's destination unless an address is given. Populates `%FIB_RESULT`, `%FIB_SMAC`, `%FIB_DMAC`, `%FIB_IP_DST`, `%FIB_IFINDEX`. (`fib-lookup6` is refused for now: the IPv6 lookup does not work yet.) The address can be a 4-byte variable in host order, as `get ip-dst` gives it (`get ip-dst D; fib-lookup %D`); `%FIB_IP_DST` comes back in the same order. Options:
  * `src <address | %VAR>` - the source to look up from (default: the packet's), so `ip rule from ...` applies; a bare `src` sets `BPF_FIB_LOOKUP_SRC`.
  * `iface <iface | %VAR>` - the incoming interface (default: the packet's).
  * `output` - look up as for a locally generated packet; `direct` - the main table, skipping ip rules; `tbid <table>` - that table (direct); `skip-neigh` - do not require a resolved neighbour.
  * `flow` - IPv4: also give the packet's protocol, TCP/UDP/SCTP ports (not for fragments) and TOS, so a multipath route is chosen per flow (`fib_multipath_hash_policy=1`) the same way the kernel chooses it, and ip rules on ports, protocol or TOS apply.
  * `ports %VAR` - IPv4: use `VAR` (low 16 bits the source port, next 16 the destination port) and protocol UDP as the multipath hash input, in place of the packet's. With `fib_multipath_hash_policy=1` a different value can select a different next hop of the route, so a program can find which next hops a route has, and keep a flow on one of them: the result can only be that next hop while it is still in the route. After `flow` it replaces the ports and protocol and keeps the TOS. `ip rule` matches on ports or protocol see these values.
  * `%FIB_RESULT`: 0 success, 1 blackhole, 2 unreachable, 3 prohibit, 4 not forwarded (e.g. a local address), 5 forwarding disabled on the interface, 7 no neighbour entry (`%FIB_IFINDEX` is still set), 8 fragmentation needed.
  * The option bits used to be one off (`output` was a direct lookup, `tbid` an output one, `src <address>` was ignored); they are the kernel's now.
* `redirect <ifname | %VAR> [egress|ingress]`, `redirect-neigh` - Terminal forwarding actions. If direction is not specified, will use same direction as attached mode.
* `clone <ifname | %VAR> [egress|ingress]` - Clone packet to specified interface. If direction is not specified, will use the same direction as attached mode.
* `encap-gre ip-src <ip> ip-dst <ip> key <val>` / `decap-gre`
* `encap-mpls label <label> bos <0|1>` / `decap-mpls` - `decap-mpls` removes one label (and a pseudowire control word when one follows) and sets the EtherType to 0x86DD when IPv6 follows, 0x0800 otherwise.
* `push-vlan <vid> [pcp]` / `pop-vlan`
* `push-qinq <outer_vid> <inner_vid> [o_pcp] [i_pcp]`
* `push-eth <d_mac|%VAR> <s_mac|%VAR>` / `pop-eth` - `push-eth` puts a new Ethernet header in front of the frame; a MAC can come from an 8-byte variable (`get src-mac S; get dst-mac D; push-eth %S %D`). `pop-eth` removes the outer Ethernet header, leaving the inner one (IP packets).

## Structural Manipulation & Checksums
* `add-bytes <offset> <len>` / `del-bytes <offset> <len>` - Insert or delete `<len>` bytes at `<offset>`, shifting the rest of the packet. `del-bytes` uses a buffer map when one can be created and falls back to an unrolled loop otherwise.
* `add-head-bytes <len>` - Add bytes at the head of the packet.
* `add-l2-bytes <len>` / `del-l2-bytes <len>` - Insert or remove `<len>` bytes right after the Ethernet header (offset 14), for any protocol; the same as `add-bytes 14 <len>` / `del-bytes 14 <len>`. For IPv4/IPv6 packets `insert-l2` / `strip-l2` are cheaper.
* `insert-l2 <len> [ethertype]` - Insert `len` zero bytes after the Ethernet header (IPv4/IPv6 packets) and optionally set the EtherType. Headers behind it keep their place in memory, so checksum offload keeps working.
* `remove-l2 <len> [ethertype]` - The counterpart of `insert-l2`: remove `len` bytes (1-64) after the Ethernet header of an IPv4/IPv6 packet and optionally set the EtherType. skb->protocol stays IPv4/IPv6 (`strip-l2` changes it), so the packet can be grown again with `insert-l2` later.
* `strip-l2 <len> <ethertype>` - Remove `len` bytes (multiple of 4) after the Ethernet header and set the EtherType, for any protocol (`bpf_skb_adjust_room` refuses non-IP packets). No payload copy; the stack sees the new protocol directly.
* `recalc-tcp-csum [l3 [max]]`, `recalc-udp-csum [l3 [max]]` - L4 checksum recomputed from scratch via `bpf_csum_diff`: any IHL, length from the IP header, packets up to `max` bytes (default 9000). On egress, locally sent TCP/UDP packets usually still have checksum offload pending (the kernel or NIC completes the checksum after the program), so recalculate on ingress or for forwarded packets.
* `calc-csum <tcp|udp> <VAR> [l3 [max]]` - Compute the correct TCP/UDP checksum into `VAR` (host order) without changing the packet.
* `ip-frag <len> <max-input-mtu>` - Fragment IP payloads into `<len>` size fragments up to `<max-input-mtu>` input size.
* `ip-defrag` - Reassemble fragmented IP packets back into a single packet.

## Constants, Macros, Includes and Unrolled Loops
A preprocessing step runs before compilation; `bpfc -E` prints its output (plain bpfc commands). Programs that use none of these keywords and no `$` compile exactly as before.

* `const <NAME> <value>` - Defines `$NAME`. A number or constant expression is stored as a number; anything else (an address, a MAC, an interface) as text. `-s NAME=VALUE` on the command line overrides it.
* `define <NAME> [PARAM ...]` ... `end-define` - A macro, used like a command: `NAME arg1 arg2`. Parameters are `$PARAM` in the body. A macro body sees only its parameters and consts; `$UNIQUE` is a number unique to each use (for labels). Macro names may contain `-` but may not be bpfc commands.
* `name <text>` - The program's name for people (up to 64 bytes): bpfcd records it, `bpfcctl status` shows it in a NAME column, and the REST API's JSON has it as `"name"`. No code is generated (`bpfc -I` prints it as `BPFC_NAME <text>`), and the filter and kernel program names (`-n`) do not change. `$` substitution applies (`name guard on $IFNAME`). The file being compiled wins over files it includes; two different names at the same level are an error.
* `include <file>` - Reads a file once (later includes of the same file are skipped). Relative names are looked up next to the including file, then in `-L` directories, then in `/etc/bpfc/include`. World-writable files are refused.
* `repeat <count> [as I]` ... `end-repeat` - The body is copied `count` times (0-4096) with `$I` = 0, 1, ...: straight-line code with no backward jump, so it loads on any kernel and needs no loop support from the verifier.
* `repeat %VAR max <count> [as I]` ... `end-repeat` - The same, but stops once `%VAR <= $I`, so it runs `%VAR` times, at most `count`. `%VAR` is checked before each copy.
* `break-repeat` / `next-repeat` - Leave the innermost repeat / skip to its next copy (a forward jump).
* `when <expr>` ... [`otherwise` ...] `end-when` - Keep one branch, decided at compile time. `defined(NAME)` tests for a const; `when <word> == <word>` (or `!=`) compares text when a side is not a number, e.g. `when $IFKIND == gre`.
* `$IFNAME`, `$IFINDEX`, `$IFTYPE`, `$IFKIND`, `$IFMAC` - The `-i` interface's name, index, device type (ARPHRD), kind (as for `dev-kind`) and MAC address, so one file can serve many interfaces (bpfcd's `%all%`): `set map CNT_$IFNAME 1 1`. `-s` overrides them.
* `$L3OFF` - Where the IP header starts: 14 behind an Ethernet header, 0 on devices whose packets start with it (device types none, GRE, IP6GRE, IPIP, IPv6 tunnel, SIT, raw IP, PPP: tun, wireguard, gre, ipip, sit, ...). bpfc reads every IP and L4 field from there by itself; `match ip`/`ip6`/`tcp`/... check the IP version instead of the EtherType; Ethernet fields and commands (MACs, `eth-proto`, VLAN, ARP, MPLS, push/pop-eth, encap/decap, strip/insert-l2, fib-lookup, ip-frag) are an error. Raw offsets (`get bytes`, `add-bytes`, `xor-packet`, ...) are frame offsets, so write them as `$(L3OFF + 9)` in a program for both kinds of device. Set by `-i`, or `-s L3OFF=0`.
* `depends <file>` - The program also depends on `file`: `bpfc -M` lists it, so bpfcd reinstalls the program when it changes. For frontends, whose input is more than the one file.
* `meta <text>` - A line for bpfcd and bpfcctl (`bpfc -I` prints `BPFC_META <text>`); generates no code. The `acl` frontend describes each entry and its counter this way.
* `option on-failure keep|remove` - For bpfcd: when a new version of this program fails, keep the running one (the default) or remove it.
* `$NAME`, `$(expr)`, `$$` - Substitution anywhere in a command, constant arithmetic (C operators and precedence on 64-bit integers; `>>` is logical), and a literal `$`. Names inside `$( )` need no `$`. A name runs until the first character that is not a letter, digit or `_`: write `$(I)_x`, not `$I_x`.

```
include fec-lib.bpfc;                   # const SHIM 8; define read-word ...
const WORDS 4;
decl W 4;
decl N 4;
get bytes 16 2 N;
repeat %N max $WORDS as I;
  get bytes $(14 + $SHIM + I*4) 4 W;
  match val %W eq 0;
    break-repeat;
  end-match;
  calc-map add WORDS $I %W;
end-repeat
```

Each copy is real code: a 250-instruction body repeated 32 times is 8,000 instructions (bpfc allows 32,768; the kernel's limit is on instructions the verifier processes, 1,000,000). Repeats suit short bodies and small counts; for long runtime loops see [Runtime loops and jumps](#runtime-loops-and-jumps).

## Runtime loops and jumps
Loops that run at run time, rather than being unrolled by `repeat`, need kernel 5.3+ (bounded loops), and the verifier must be able to see that they end.
* `start-loop` ... `loop <VAR>` - Jump back to `start-loop` while `VAR` is not zero.
* `set-reg-loop <n | %VAR>`, `dec-reg-loop`, `loop-reg` - The same with the loop register: set it, decrement it, and jump back to `start-loop` while it is not zero.
* `label <NAME>` / `goto <NAME>` - Jump to a label: forward, or back for a loop the verifier can bound. Inside a `define`, use `$UNIQUE` in label names so each use of the macro gets its own.

## Diagnostics and logging
* `debug-log <string>` - Writes to `/sys/kernel/debug/tracing/trace_pipe`.
* `ringbuf-map <MAP> [bytes]` - Declare a ring buffer (default 262144 bytes, a power of two; kernel 5.8+) for `log`.
* `log <MAP> <id | %VAR> [bytes]` - Put one record in the ring buffer: the time (ns, CLOCK_MONOTONIC, 8 bytes), the id (8), the interface index (4), the packet length (4), then the first `bytes` (default 96, a multiple of 8 up to 256) of the frame, zero padded. A full buffer drops the record. Rate-limit it (`match seen`) for anything but rare events. `bpfcctl log` reads the ACL frontend's records this way.
