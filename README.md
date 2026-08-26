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
* `continue` - Terminal. Closes local block, exits eBPF, and tells kernel to evaluate the next TC rule.
* `drop` - Terminal. Closes local block, exits eBPF, and silently drops the packet.
* `reclassify` - Terminal. Restarts TC evaluation from rule 0.

### Protocol Shorthands
Quick boolean filters for specific L2/L3 types. Use as standalone matches (e.g., `match tcp;`).
* Supported: `ip`, `ip6`, `arp`, `icmp`, `gre`, `tcp`, `udp`, `igmp`, `ospf`, `pim`, `esp`, `rsvp`, `l2tp`.

### Packet Data Fields (`get`, `set`, `match`)
Fields support extraction (`get <field> <VAR>`), assignment (`set <field> <val | %VAR>`), and evaluation (`match <field> <val | %VAR>`). Subnets (`10.0.0.0/24`) and port ranges (`80-100`) are fully supported.

* **L2:** `dst-mac`, `src-mac`, `eth-proto`, `vlan-id`
* **IPv4:** `ip-src`, `ip-dst`, `ip-tos`, `ip-proto`
* **IPv6:** `ip6-src`, `ip6-dst`, `ip6-tclass`, `ip6-flow`, `ip6-proto`
* **L4:** `tcp-src`, `tcp-dst`, `udp-src`, `udp-dst`
* **ARP:** `arp-htype`, `arp-ptype`, `arp-hlen`, `arp-plen`, `arp-oper`, `arp-sha`, `arp-tha`, `arp-spa`, `arp-tpa`
* **MPLS:** `mpls-label`, `mpls-bos`
* **GRE:** `gre-key`
* **Generic:** `bytes <offset> <length>`

### Context Metadata (`__sk_buff`)
* `skb-mark` - Netfilter/iptables firewall mark (`u32`).
* `skb-hash` - RPS flow hash (`u32`).
* `skb-cb <0-4>` - 20-byte control buffer array (5x `u32` slots) for passing state across tail-calls.
* `queue` - Hardware TX queue mapping (`set` only).

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

### Routing & Forwarding
* `fib-lookup [direct|output] [tbid] [skip-neigh] [src] [mark]` - Queries kernel routing tables. Populates `%FIB_RESULT`, `%FIB_SMAC`, `%FIB_DMAC`, `%FIB_IP_DST`, `%FIB_IP6_DST`, `%FIB_IFINDEX`.
* `redirect <ifname | %VAR>`, `redirect-egress`, `redirect-neigh`, `clone-redirect` - Terminal forwarding actions.
* `encap-gre ip-src <ip> ip-dst <ip> key <val>` / `decap-gre`
* `encap-mpls <label> <bos>` / `decap-mpls`
* `push-vlan <vid> [pcp]` / `pop-vlan`
* `push-qinq <outer_vid> <inner_vid> [o_pcp] [i_pcp]`
* `push-eth <d_mac> <s_mac>` / `pop-eth`

### Structural Manipulation & Checksums
* `add-bytes <offset> <len>` / `del-bytes <offset> <len>` - Shifts packet tail down/up.
* `add-l2-bytes <len>` / `del-l2-bytes <len>` - Shifts memory exactly at Offset 14.
* `recalc-tcp-csum`, `recalc-udp-csum`, `recalc-icmp-csum` - Stack-safe L4 recalculations via `bpf_csum_diff`.

### Diagnostics
* `debug-log <string>` - Writes to `/sys/kernel/debug/tracing/trace_pipe`.

---

## Advanced Examples

### 1. Stateful Firewall & Port Translation (DNAT)
Intercept TCP traffic, enforce a connection rate limit via Maps, and dynamically translate the destination port.
\`\`\`bash
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
\`\`\`

### 2. ARP Spoofing / Reflection
Intercept an ARP Request, flip it to a Reply, dynamically swap addresses, and reflect it out the same interface.
\`\`\`bash
./bpf_compiler -i eth0 -p 5 -d ingress "match arp; match arp-oper 1; \
    get arp-sha S_MAC; get arp-spa S_IP; get arp-tpa T_IP; \
    set arp-oper 2; \
    set arp-tha %S_MAC; set arp-tpa %S_IP; \
    set arp-sha aa:bb:cc:dd:ee:ff; set arp-spa %T_IP; \
    redirect-egress eth0"
\`\`\`

### 3. SD-WAN Policy Routing (FIB Lookup + GRE)
Route UDP 5060 (VoIP) out a fast link, and GRE tunnel everything else via the routing table.
\`\`\`bash
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
\`\`\`

