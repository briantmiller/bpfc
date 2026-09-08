# Programmable eBPF Network Fabric Compiler

A standalone, LLVM/Clang-independent eBPF assembler and direct network fabric loader written in pure C. This tool parses a custom, semicolon-separated instruction set to generate raw eBPF bytecode, securely load it into the Linux kernel, and bind it to network interfaces via raw Netlink TC `clsact` queuing disciplines.

Built for Red Team operations, SD-WAN edge routing, and high-performance network programming, it supports dynamic variables, stateful map sharing, nested branching logic, and on-the-fly L2-L4 encapsulation.

---

## Requirements
* Linux kernel 4.18+ (Includes native RHEL 8 / CentOS 8 verifier compatability)
* Root privileges (`CAP_NET_ADMIN` / `CAP_SYS_ADMIN`)

---

## Usage & CLI Flags

```bash
# Install to an interface
sudo ./bpf_compiler -i <interface> [-d ingress|egress] [-p <priority>] [-m <map_dir>] [-v] "<instructions>"

# Clean / Detach from an interface
sudo ./bpf_compiler -i <interface> -c
```

| Flag | Description |
| :--- | :--- |
| `-i <iface>` | Target network interface (e.g., `eth0`). If omitted, compiles to `output.bpf` locally. |
| `-d <dir>` | Hook direction: `ingress` (default) or `egress`. |
| `-p <prio>` | TC filter execution priority (e.g., `1`). Allows multiple stacked programs to execute sequentially. |
| `-m <dir>` | Path to store pinned eBPF maps (e.g., `/sys/fs/bpf/my_ns/`). Crucial for network namespaces. |
| `-c` | Cleanup mode. Atomically deletes the `clsact` qdisc, detaching all filters from the interface. |
| `-v` | Verbose mode. Prints a trace of jump offset calculations and block resolutions. |

---

## Language Syntax

Instructions are strictly **semicolon-separated**. Variables (denoted by `%`) are dynamically allocated on the 512-byte eBPF stack and natively converted to Host Byte Order for mathematical operations.

### Branching & Control Flow
* `match <field> <value>` - Opens a conditional block. If the packet field does not match the value, execution jumps past the block.
* `match val %VAR <op> <val | %VAR>` - Compares variables logically (`lt`, `gt`, `le`, `ge`, `eq`, `ne`).
* `end-match` - Closes the most recent conditional `match` block.
* `continue` - Terminal. Closes most recent match block, exits eBPF, and tells kernel to evaluate the next TC rule.
* `drop` - Terminal. Closes most recent match block, exits eBPF, and silently drops the packet.
* `reclassify` - Terminal. Closes most recent match block. Restarts TC evaluation from rule 0.

### Protocol Shorthands
Quick boolean filters for specific L2/L3 types. Use as standalone matches (e.g., `match tcp;`).
* Supported: `ip`, `ip6`, `arp`, `icmp`, `gre`, `tcp`, `udp`, `igmp`, `ospf`, `pim`, `esp`, `rsvp`, `l2tp`, `vlan`, `qinq`.

### Packet Data Fields (`get`, `set`, `match`)
Fields support extraction (`get <field> <VAR>`), assignment (`set <field> <val | %VAR>`), and evaluation (`match <field> <val | %VAR>`). Subnets (`10.0.0.0/24`) and port ranges (`80-100`) are fully supported.

* **L2:** `dst-mac`, `src-mac`, `eth-proto`, `vlan-id`
* **IPv4:** `ip-src`, `ip-dst`, `ip-tos`, `ip-proto`
* **IPv6:** `ip6-src`, `ip6-dst`, `ip6-tclass`, `ip6-flow`, `ip6-proto`
* **L4:** `tcp-src`, `tcp-dst`, `udp-src`, `udp-dst`
* **ARP:** `arp-htype`, `arp-ptype`, `arp-hlen`, `arp-plen`, `arp-oper`, `arp-sha`, `arp-tha`, `arp-spa`, `arp-tpa`
* **MPLS:** `mpls-label`, `mpls-bos`
* **GRE:** `gre-key`, `gre-proto`
* **Generic:** `bytes <offset> <length>`

### Context Metadata (`__sk_buff`)
* `len` - Packet length (`u32`).
* `protocol` - Protocol stored in sk_buff.
* `skb-ifindex` - Interface number associated with sk_buff.
* `skb-ingress` - Ingress interface number associated with sk_buff.
* `skb-mark` - Netfilter/iptables firewall mark (`u32`).
* `skb-hash` - RPS flow hash (`u32`).
* `skb-cb <0-4>` - 20-byte control buffer array (5x `u32` slots) for passing state across tail-calls.
* `queue` - Hardware TX queue mapping.

### ALU Math Engine (`calc`)
Performs mathematically-safe eBPF operations on standard 32/64-bit variables.
* `calc <op> <DST_VAR> <val | %SRC_VAR>`
* Operators: `add`, `sub`, `mul`, `div`, `or`, `and`, `lsh`, `rsh`, `mod`, `xor`
* `calc not <VAR>` - Unary bitwise inversion.
* `calc bswap <VAR> <bits>` - Flips byte order (16, 32, or 64 bits).

### eBPF Maps (State Tracking)
Allows persistent data storage across packets and network interfaces.
* `get map <MAP_NAME> <key | %VAR> <VAL_DST_VAR>` - Loads value into variable (defaults 0 if missing).
* `set map <MAP_NAME> <key | %VAR> <val | %VAR>` - Updates or creates a 64-bit map entry.
* `save-packet <MAP_NAME> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Save packet data of specified length into a per-CPU map.
* `save-packet-keyed <MAP_NAME> <key | %VAR> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Save packet data of specified length into a global map into key number specified, allowing for storing packet contents for later recovery.
* `load-packet <MAP_NAME> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Load data of specified length from per-CPU map into packet.
* `load-packet-keyed <MAP_NAME> <key | %VAR> <len | %VAR> [src-offset | %VAR [dst-offset | %VAR]]` - Load data of specified length from keyed map into packet.

### Routing & Forwarding
* `fib-lookup [direct|output] [tbid] [skip-neigh] [src] [mark]` - Queries kernel routing tables. Populates `%FIB_RESULT`, `%FIB_SMAC`, `%FIB_DMAC`, `%FIB_IP_DST`, `%FIB_IP6_DST`, `%FIB_IFINDEX`.
* `redirect <ifname | %VAR>`, `redirect-egress`, `redirect-neigh`, `clone-redirect` - Terminal forwarding actions.
* `encap-gre ip-src <ip> ip-dst <ip> key <val>` / `decap-gre`
* `encap-mpls <label> <bos>` / `decap-mpls`
* `push-vlan <vid> [pcp]` / `pop-vlan`
* `push-qinq <outer_vid> <inner_vid> [o_pcp] [i_pcp]`
* `push-eth <d_mac> <s_mac>` / `pop-eth`

### Structural Manipulation & Checksums
* `add-bytes <offset> <len>` / `del-bytes <offset> <len>` - Inserts `<len>` number of bytes at `<offset>` and shifts packet tail down/up.
* `add-head-bytes <len>` - Adds bytes to head of packet.
* `del-bytes <offset> <len>` - Delete bytes at specific offset. Will attempt to use buffer maps if available, then revert to unrolled loop if necessary.
* `add-l2-bytes <len>` / `del-l2-bytes <len>` - Shifts memory exactly at Offset 14. Possibly not working depending on kernel version.
* `recalc-tcp-csum`, `recalc-udp-csum`, `recalc-icmp-csum` - Stack-safe L4 recalculations via `bpf_csum_diff`.
* `ip-frag <len> <max-input-mtu>` - Fragment IP payloads into `<len>` size fragments up to `<max-input-mtu>` input size.  
* `ip-defrag` - Reassemble fragmented IP packets back into a single packet. 

### Diagnostics
* `debug-log <string>` - Writes to `/sys/kernel/debug/tracing/trace_pipe`.

---

## Advanced Examples

### 1. Stateful Firewall & Port Translation (DNAT)
Intercept TCP traffic, enforce a connection rate limit via Maps, and dynamically translate the destination port.
```bash
./bpf_compiler -i eth0 -p 10 "match tcp; \
    get ip-src SRC; \
    get map DDOS_BLOCK %SRC COUNT; \
    match val %COUNT gt 5000; debug-log BLOCKED; drop; end-match; \
    calc add COUNT 1; set map DDOS_BLOCK %SRC %COUNT; \
    match tcp-dst 80; \
        set tcp-dst 8080; \
        redirect-neigh eth1; \
    end-match; \
    continue"
```

### 2. ARP Spoofing / Reflection
Intercept an ARP Request, flip it to a Reply, dynamically swap addresses, and reflect it out the same interface.
```bash
./bpf_compiler -i eth0 -p 5 -d ingress "match arp; match arp-oper 1; \
    get arp-sha S_MAC; get arp-spa S_IP; get arp-tpa T_IP; \
    set arp-oper 2; \
    set arp-tha %S_MAC; set arp-tpa %S_IP; \
    set arp-sha aa:bb:cc:dd:ee:ff; set arp-spa %T_IP; \
    redirect-egress eth0"
```

### 3. SD-WAN Policy Routing (FIB Lookup + GRE)
Route UDP 5060 (VoIP) out a fast link, and GRE tunnel everything else via the routing table.
```bash
./bpf_compiler -i eth0 -d ingress "match ip; \
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

### 4. MPLS pseudowires
Encapsulate all packets on an interface eth1 within MPLS pseudowire of label 16 and next-hop label of 20 and send to 10.0.0.6.
```bash
./bpf_compiler -i eth1 -d ingress "decl MPLS1 4; \
decl MPLS2 4; \
fib-lookup 10.0.0.6; \ 
match val %FIB_RESULT eq 0; \
        add-head-bytes 22; \
        #Next-hop label \
        set val MPLS1 20; \
        calc lsh MPLS1 3; \
	#MPLS TC \
        calc or MPLS1 0; \
        calc lsh MPLS1 1; \
        #Bottom of stack is zero on next-hop label \
        calc or MPLS1 0; \
        calc lsh MPLS1 8; \
        #TTL \
        calc or MPLS1 225; \
        calc bswap MPLS1; \
	#MPLS lable 16 \
        set val MPLS2 16; \
        calc lsh MPLS2 3; \
	#MPLS TC \
        calc or MPLS2 0; \
        calc lsh MPLS2 1; \
        #MPLS bottom of stack \
        calc or MPLS2 1; \
        calc lsh MPLS2 8; \
        #TTL \
        calc or MPLS2 225; \
        calc bswap MPLS2; \
        set bytes 14 4 %MPLS1; \
        set bytes 18 4 %MPLS2; \
        set eth-proto 0x8847; \
        set dst-mac %FIB_DMAC; \
        set src-mac %FIB_SMAC; \
        redirect %FIB_IFINDEX egress"
```

Decapsulate pseudowire packets and send to interface eth2 - assume next-hop label `20` has been stripped off by PE router. 
```bash
./bpf_compiler -i eth0 -d ingress "match mpls; \
        match mpls-label 16; \
        del-bytes 0 18; \
        redirect eth2 egress"
```

If control-words are desired, change `add-head-bytes 22` to `add-head-bytes 26` and `del-bytes 0 18` to `del-bytes 0 22` to account for the 4-byte control word.

Note: The above MPLS encapsulation is not compatible with TCP Generic Receive Offload (GRO) or TCP Segmentation Offload (TSO). This is due to the behavior of combining multiple TCP segments into a single sk_buff and then processing that single sk_buff for all segments.  When this occurs, the large chunk of segments is encapsulated into the single MPLS packet often resulting in a packet larger than the interface MTU.  To overcome this, disable GRO and TSO on the interface using `ethtool -K eth1 tso off gro off`.

### 5. Network Address Translation (NAT)


Outgoing:
* Create a `FLOW_KEY` variable using layer-3 and layer-4 information that is unique to flow and store the source IP address.
* Change the packet source IP address to the WAN facing IP address. 

Incoming:
* Lookup the original source IP address using the same `FLOW_KEY` fields, but reverse source & destination where appropriate.
* Change the packet destination IP address to the original source IP address referenced by `FLOW_KEY`

This implementation uses the normal Linux routing FIB, so there is no need to do FIB lookups or redirection in eBPF.

NAT ICMP traffic on eth0
```bash
#Store ICMP "echo request" flow information into map and change source IP to address of eth0
bpf_compiler -i eth0 -d egress -p 100 "\
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
bpf_compiler -i eth0 -d ingress -p 100 "\
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
bpf_compiler -i eth0 -d egress -p 160 "\
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
bpf_compiler -i eth0 -d egress -p 164 'match tcp; set ip-src 10.0.0.30'

#Change the IP destination of TCP packets received on eth0 to NAT'ed address
bpf_compiler -i eth0 -d ingress -p 160 "\
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
bpf_compiler -i eth0 -d egress -p 117 "\
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
bpf_compiler -i eth0 -d ingress -p 117 "\
match udp; \
	decl FLOW_KEY 8; \
	get ip-src FLOW_KEY; \
	get udp-dst UDP_DST; \
	calc bswap FLOW_KEY; \
	calc or FLOW_KEY %UDP_DST; \
	get map UDP_NAT %FLOW_KEY IP_DST; \
	set ip-dst %IP_DST"
```
