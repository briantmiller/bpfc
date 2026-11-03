# Programmable eBPF Network Fabric Compiler & Dataplane

A standalone, LLVM/Clang-independent eBPF assembler and dataplane written in pure C with zero library dependencies. This tool parses a custom, semicolon-separated instruction set to generate raw eBPF bytecode, load/verify into the kernel, and bind it to network interfaces via raw Netlink TC `clsact` queuing disciplines.

Designed to be a deployable eBPF dataplane and networking swiss army knife.  Useful for Red Team operations, SD-WAN edge routing, and high-performance network programming, it supports dynamic variables, stateful map sharing, nested branching logic, and on-the-fly L2-L4 encapsulation.

---

## Requirements
* Linux kernel 4.18+ (Includes native RHEL 8 / CentOS 8 verifier compatability)
* Root privileges (`CAP_NET_ADMIN` / `CAP_SYS_ADMIN`)

---

## Usage & CLI Flags

```bash
# Install to an interface
sudo ./bpfc -i <interface> [-d ingress|egress] [-p <priority>] [-m <map_dir>] [-v] "<instructions>"

# Clean / Detach from an interface
sudo ./bpfc -i <interface> -c
```

| Flag | Description |
| :--- | :--- |
| `-i <iface>` | Target network interface (e.g., `eth0`). If omitted, compiles to `output.bpf` locally. |
| `-d <dir>` | Hook direction: `ingress` (default) or `egress`. |
| `-p <prio>` | TC filter execution priority (e.g., `1`). Allows multiple stacked programs to execute sequentially. Re-running with the same priority replaces the program atomically. |
| `-m <dir>` | Path to store pinned eBPF maps (e.g., `/sys/fs/bpf/my_ns/`). Crucial for network namespaces. |
| `-f <file>` | Read instructions from a file (`-` for stdin). `#` comments run to the end of the line. |
| `-c` | Cleanup mode. Atomically deletes the `clsact` qdisc, detaching all filters from the interface. |
| `-D` | Delete only the program at `-p <prio>` on `-d <dir>`. |
| `-n <name>` | Name the TC filter and the kernel program (shown by `tc filter show` and `bpftool prog`). |
| `-I` | Print a `BPFC_INFO id=... tag=...` line after attaching. |
| `-r <map>` | Dump the contents of a pinned map. |
| `-w <map> <key> <value>` | Write a 64-bit value into a pinned map (e.g. runtime settings). |
| `-v` | Verbose mode. Prints a trace of jump offset calculations and block resolutions. |
| `-E` | Print the program after `include`, `const`, `define`, `repeat` and `when` are expanded, then exit. |
| `-s <NAME>=<value>` | Set `const NAME`, overriding the program's own value. Repeatable. |
| `-L <dir>` | Search `dir` for include files (before `/etc/bpfc/include`). Repeatable. |
| `-M` | Print the program file and every file it includes, one per line, then exit. |

---

## bpfcd: managing programs from files

`bpfcd` keeps programs from `/etc/bpfc/interfaces.d` attached, so they survive reboots and interface re-creation:

```
/etc/bpfc/interfaces.d/<interface>/ingress/<priority>.bpfc
/etc/bpfc/interfaces.d/<interface>/egress/<priority>.bpfc
```

```bash
mkdir -p /etc/bpfc/interfaces.d/eth0/ingress
printf 'match tcp;\n  match tcp-dst 23;\n    drop\n' > /etc/bpfc/interfaces.d/eth0/ingress/100.bpfc
systemctl enable --now bpfcd
bpfcctl                      # what is installed, from which file, and whether the kernel agrees
bpfcctl show eth0 ingress 100 --bytecode
```

* **Reload** (`systemctl reload bpfcd` or `bpfcctl reload`): new and changed files are installed (atomic replace at the same priority), deleted files are detached. A file is only re-hashed when its mtime changes and only reinstalled when its SHA-256 differs. A program that uses `include` is hashed together with the files it includes (as listed by `bpfc -M`) on every reload, so editing a shared library reinstalls every program that uses it. Keep libraries outside `interfaces.d` (for example in `/etc/bpfc/include`), or bpfcd will try to install them as programs.
* **Failures**: if a file does not compile or the verifier rejects it, its priority is left empty rather than running the old version; `bpfcctl show` prints the verifier log.
* **Interfaces**: programs are installed when a configured interface appears and re-installed when it is re-created.
* **External changes**: if something else removes or replaces a managed program, bpfcd reinstalls it or only logs it, per `on_external_change` in `/etc/bpfc/bpfc.conf`.
* **Tracking**: each program's id and tag are recorded with its file path and hash in `/run/bpfc/state`; filters are named `bpfcd:<iface>/<dir>/<prio>`.

See `bpfcd(8)`, `bpfcctl(8)` and `bpfc.conf(5)`. Build an RPM (RHEL 9/10) with `make rpm`; run the daemon's integration and container tests with `make check` (root).

**Tests.** `./test.sh` runs every suite (root; about an hour) and ends with pass/fail/skip totals per suite; it exits non-zero if anything failed. Name suites to run only those (`./test.sh bpfc nat`), add `-f` to print failures only, or `-v` for each suite's full output; logs are kept under `/tmp/bpfc-tests.*`. `make check` (preprocessor, stack, bpfcd, container), `make check-dataplane` and `make check-all` use the same runner; pass flags with `make check TESTFLAGS=-f`. Suites skip (rather than fail) when they are not run as root or need something the system lacks: a tool (tcpdump, ncat, iperf), kernel MPLS routing (`mpls_router`), or scapy for `tests/test_bpfc.py`. The fragmentation suites check each fragment size with three ordinary pings and, separately, the loss under load (100 parallel pings), which must stay below `STRESS_MAX_LOSS` hundredths of a percent (default 100, i.e. 1 %). New shell suites should `source tests/lib.sh` for `test_pass`/`test_fail`/`test_skip`, `check` and `tests_exit`.

**Containers (no systemd):** the `bpfc-container` package adds `/usr/sbin/bpfcd-entrypoint`, which runs bpfcd as the container's PID 1. Neither package requires systemd, and settings can be passed as `BPFCD_*` environment variables. See [dist/container/README.md](dist/container/README.md) for an example Containerfile and run options. `make rpm RPMBUILD_OPTS="--with static"` builds statically linked binaries for images without a matching libc.

---

## Dataplane: FEC, ARQ, in-band telemetry and bandwidth probing

`dataplane/bpfc-dataplane-gen` generates bpfc programs for a point-to-point Layer-2 link (both ends run them): every IPv4 packet gets an 8-byte shim (EtherType 0x88B5) with a sequence number and timestamp. The receiver measures loss, reordering, duplicates, jitter and queueing delay (no clock synchronisation needed) and reports back once a second. When loss crosses a threshold the sender adds XOR parity (forward error correction), scaled to the loss, and turns it off again after a cool-down; lost packets are also retransmitted from a short buffer (ARQ), and packet-pair probes estimate the link capacity. Each interface has its own maps.

The two scripts are plain bash and are not part of the RPM; copy them to e.g. `/usr/local/sbin`.

Profiles set the defaults for a kind of link (`direct`, `wan`, `geo` built in; your own in `/etc/bpfc/dataplane/profiles.d/`), and `--link-rate` / `--rtt` size the retransmit ring and windows.

```bash
bpfc-dataplane-gen -i eth0 --profile geo   # writes /etc/bpfc/interfaces.d/eth0/{egress,ingress}/*.bpfc
bpfc-dataplane-gen --list-profiles
bpfc-dataplane-gen --show-profile geo --rtt 650ms   # effective settings and buffer sizes
bpfc-dataplane-gen -i eth0 --setup-hints   # MTU / offload settings for the link
systemctl reload bpfcd
bpfc-dataplane-status                      # link quality and what FEC/ARQ are doing, per interface
bpfc-dataplane-status set eth0 fec-threshold 2
```

See [dataplane/DESIGN.md](dataplane/DESIGN.md) for the wire format, the algorithms and the limits; `make check-dataplane` (root) runs its end-to-end tests.

---

## Language Syntax

Instructions are strictly **semicolon-separated**. Variables (denoted by `%`) are dynamically allocated on the 512-byte eBPF stack and natively converted to Host Byte Order for mathematical operations.

### Variables
* `decl <VAR> <size>` - Create a new variable of `<size>` bytes (1,2,4 or 8).
* `set val <VAR> <%VAR | int>` - Set variable to integer value or value from another variable
* `free <VAR>` - Free `VAR` from the stack, making space available for later variables.  

**Stack layout.** The 512-byte stack holds 128 bytes of fixed scratch used inside single instructions, then one 8-byte slot per variable (whatever its size), as many as the program declares, up to 48. Instructions that need more scratch (`fib-lookup`: 72 bytes, `push-eth`: 32, `recalc-icmp-csum`: 128, the byte-insertion and deletion commands) take it below the variables and give it back when they finish. `xor-packet` and the TCP/UDP checksums stage packet data in chunks of up to 256 bytes: with more than 16 variables the chunks get smaller (down to 8 and 4 bytes), which works the same but costs more verifier instructions. The variables `fib-lookup` adds (`FIB_RESULT`, `FIB_SMAC`, `FIB_DMAC`, `FIB_IP_DST`, `FIB_IFINDEX`) count as five. If something does not fit, bpfc says which instruction needs how much; `free` variables you no longer need.

### Branching & Control Flow
* `match|if <field> <value>` - Opens a conditional block. If the packet field does not match the value, execution jumps past the block.
* `match|if val %VAR <op> <val | %VAR>` - Compares variables logically (`lt`, `gt`, `le`, `ge`, `eq`, `ne`). `seq-lt`, `seq-le`, `seq-gt`, `seq-ge` compare 32-bit wrapping counters such as TCP sequence numbers (serial-number order, RFC 1982: A is before B when `(int32)(A - B) < 0`), valid while the two are less than 2^31 apart.
* `else` - Inverse of match/if criteria.
* `end-match|end-if` - Closes the most recent conditional `match` block.
* `continue` - Terminal. Exits eBPF, and tells kernel to evaluate the next TC rule.
* `drop` - Terminal. Exits eBPF, and silently drops the packet.
* `reclassify` - Terminal. Restarts TC evaluation from rule 0.

Note - Terminal commands must be last command in program or be followed by 'end-match', 'else' or 'end-if'.

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
* **TCP (IPv4, any IHL; `get` only):** `tcp-seq`, `tcp-ack`, `tcp-flags` (the flags byte: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10), `tcp-win` (unscaled), `tcp-hlen` (header length incl. options, bytes). 0 when the packet is not IPv4 TCP.
* **Offsets and lengths (IPv4, any IHL; `get` only):** `l4-off` (offset of the TCP/UDP/... header in the frame), `payload-off` (TCP: after the options, UDP: after 8 bytes), `payload-len` (from the IP total length, so Ethernet padding is not counted). Use them with variable offsets: `get bytes %OFF 4 V`.
* **Flow key (`get` only):** `flow-key [reverse | symmetric]` - 64-bit hash of the IPv4 addresses, protocol and TCP/UDP ports (never 0; 0 for non-IPv4). `reverse` is the key of the opposite direction, so a returning ACK finds its data flow's map entry; `symmetric` is the same key for both directions.
* **Generic:** `bytes <offset | %VAR> <length>` - with a variable offset the bytes are read with `bpf_skb_load_bytes` (0 if outside the packet) and written with `bpf_skb_store_bytes` (nothing written if outside).

### Context Metadata (`__sk_buff`)
* `len` - Packet length (`u32`).
* `protocol` - Protocol stored in sk_buff.
* `skb-ifindex` - Interface number associated with sk_buff.
* `skb-ingress` - Ingress interface number associated with sk_buff.
* `skb-mark` - Netfilter/iptables firewall mark (`u32`).
* `skb-hash` - RPS flow hash (`u32`).
* `tstamp` - `skb->tstamp`, 64-bit ns. On egress, a time in the future (CLOCK_MONOTONIC, as `get time`) holds the packet until then under the fq qdisc (earliest-departure-time pacing).
* `skb-cb <0-4>` - 20-byte control buffer array (5x `u32` slots) for passing state across tail-calls and to the next TC priority.
* `cpu` - (`get` only) number of the CPU running the program.
* `queue` - Hardware TX queue mapping.

### ALU Math Engine (`calc`)
Performs mathematically-safe eBPF operations on standard 32/64-bit variables.
* `calc <op> <DST_VAR> <val | %SRC_VAR>`
* Operators: `add`, `sub`, `mul`, `div`, `or`, `and`, `lsh`, `rsh`, `mod`, `xor`
* `calc not <VAR>` - Unary bitwise inversion.
* `calc bswap <VAR> <bits>` - Flips byte order (16, 32, or 64 bits).
* `calc hton <VAR> [bits]` / `calc ntoh <VAR> [bits]` - Host/network byte order. `get bytes` returns host order; `set bytes` with a variable writes it as stored, so convert first.

### eBPF Maps (State Tracking)
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
* `tcp-option <kind | %VAR> <OFF_VAR> [LEN_VAR]` - Walks the TCP options (IPv4, any IHL) and sets `OFF_VAR` to the frame offset of the first option of that kind and `LEN_VAR` to its length byte; both 0 if there is none. Read or change the option with `get bytes` / `set bytes` / `fill-bytes` at `%OFF_VAR`.
* `fill-bytes <offset | %VAR> <len | %VAR> <byte | %VAR>` - Overwrite 1-64 packet bytes with one value (e.g. 1 to turn TCP options into NOPs). Nothing is written when the length is 0 or over 64, or the range is outside the packet. Checksums are not updated: on egress, locally sent TCP/UDP still has its checksum completed after the program (over the bytes as rewritten), so leave it; for forwarded or received packets follow with `recalc-tcp-csum`.
* `calc-map <add|or|and|xor|xchg> <MAP_NAME> <key | %VAR> <val | %VAR> [OLD_VAR]` - Atomic update of a 64-bit map value (created as 0); `OLD_VAR` receives the previous value. Safe when several CPUs update the same key, unlike `get map` + `set map`.
* `xor-packet <MAP_NAME> <len> [src [dst]]` / `xor-packet-keyed <MAP_NAME> <key> <len> [src [dst]]` - XOR packet bytes into a buffer (atomically; dst is a multiple of 8). Building block for XOR parity / FEC.
* `zero-buffer <MAP_NAME> <len> [dst]` / `zero-buffer-keyed <MAP_NAME> <key> <len> [dst]` - Zero part of a buffer.

### Routing & Forwarding
* `fib-lookup [direct|output] [tbid] [skip-neigh] [src] [mark]` - Queries kernel routing tables. Populates `%FIB_RESULT`, `%FIB_SMAC`, `%FIB_DMAC`, `%FIB_IP_DST`, `%FIB_IP6_DST`, `%FIB_IFINDEX`.
* `redirect <ifname | %VAR> [egress|ingress]`, `redirect-neigh` - Terminal forwarding actions. If direction is not specified, will use same direction as attached mode.
* `clone <ifname | %VAR> [egress|ingress]` - Clone packet to specified interface. If direction is not specified, will use the same direction as attached mode.
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
* `insert-l2 <len> [ethertype]` - Insert `len` zero bytes after the Ethernet header (IPv4/IPv6 packets) and optionally set the EtherType. Headers behind it keep their place in memory, so checksum offload keeps working.
* `strip-l2 <len> <ethertype>` - Remove `len` bytes (multiple of 4) after the Ethernet header and set the EtherType, for any protocol (`bpf_skb_adjust_room` refuses non-IP packets). No payload copy; the stack sees the new protocol directly.
* `recalc-tcp-csum [l3 [max]]`, `recalc-udp-csum [l3 [max]]`, `recalc-icmp-csum` - L4 checksum recomputed from scratch via `bpf_csum_diff`: any IHL, length from the IP header, packets up to `max` bytes (default 9000). On egress, locally sent TCP/UDP packets usually still have checksum offload pending (the kernel or NIC completes the checksum after the program), so recalculate on ingress or for forwarded packets.
* `calc-csum <tcp|udp> <VAR> [l3 [max]]` - Compute the correct TCP/UDP checksum into `VAR` (host order) without changing the packet.
* `ip-frag <len> <max-input-mtu>` - Fragment IP payloads into `<len>` size fragments up to `<max-input-mtu>` input size.  
* `ip-defrag` - Reassemble fragmented IP packets back into a single packet. 

### Constants, Macros, Includes and Unrolled Loops
A preprocessing step runs before compilation; `bpfc -E` prints its output (plain bpfc commands). Programs that use none of these keywords and no `$` compile exactly as before.

* `const <NAME> <value>` - Defines `$NAME`. A number or constant expression is stored as a number; anything else (an address, a MAC, an interface) as text. `-s NAME=VALUE` on the command line overrides it.
* `define <NAME> [PARAM ...]` ... `end-define` - A macro, used like a command: `NAME arg1 arg2`. Parameters are `$PARAM` in the body. A macro body sees only its parameters and consts; `$UNIQUE` is a number unique to each use (for labels). Macro names may contain `-` but may not be bpfc commands.
* `include <file>` - Reads a file once (later includes of the same file are skipped). Relative names are looked up next to the including file, then in `-L` directories, then in `/etc/bpfc/include`. World-writable files are refused.
* `repeat <count> [as I]` ... `end-repeat` - The body is copied `count` times (0-4096) with `$I` = 0, 1, ...: straight-line code with no backward jump, so it loads on any kernel and needs no loop support from the verifier.
* `repeat %VAR max <count> [as I]` ... `end-repeat` - The same, but stops once `%VAR <= $I`, so it runs `%VAR` times, at most `count`. `%VAR` is checked before each copy.
* `break-repeat` / `next-repeat` - Leave the innermost repeat / skip to its next copy (a forward jump).
* `when <expr>` ... [`otherwise` ...] `end-when` - Keep one branch, decided at compile time. `defined(NAME)` tests for a const.
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

Each copy is real code: a 250-instruction body repeated 32 times is 8,000 instructions (bpfc allows 32,768; the kernel's limit is on instructions the verifier processes, 1,000,000). Repeats suit short bodies and small counts; `start-loop`/`loop` remains for long runtime loops on kernels 5.3+.

### Diagnostics
* `debug-log <string>` - Writes to `/sys/kernel/debug/tracing/trace_pipe`.

---

## Advanced Examples

### 1. ARP Spoofing / Reflection
Intercept an ARP Request, flip it to a Reply, dynamically swap addresses, and reflect it out the same interface.
```bash
./bpfc -i eth0 -p 5 -d ingress "match arp; match arp-oper 1; \
    get arp-sha S_MAC; get arp-spa S_IP; get arp-tpa T_IP; \
    set arp-oper 2; \
    set arp-tha %S_MAC; set arp-tpa %S_IP; \
    set arp-sha aa:bb:cc:dd:ee:ff; set arp-spa %T_IP; \
    redirect-egress eth0"
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
Encapsulate all packets on an interface eth1 within MPLS pseudowire of label 16 and next-hop label of 20 and send to 10.0.0.6.
```bash
./bpfc -i eth1 -d ingress "decl MPLS1 4; \
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
./bpfc -i eth0 -d ingress "match mpls; \
        match mpls-label 16; \
        del-bytes 0 18; \
        redirect eth2 egress"
```

If control-words are desired, change `add-head-bytes 22` to `add-head-bytes 26` and `del-bytes 0 18` to `del-bytes 0 22` to account for the 4-byte control word.

Note: The above MPLS encapsulation is not compatible with TCP Generic Receive Offload (GRO) or TCP Segmentation Offload (TSO). This is due to the behavior of combining multiple TCP segments into a single sk_buff and then processing that single sk_buff for all segments.  When this occurs, the large chunk of segments is encapsulated into the single MPLS packet often resulting in a packet larger than the interface MTU.  To overcome this, disable GRO and TSO on the interface using `ethtool -K eth1 tso off gro off`.

### 4. Network Address Translation (NAT)


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

### 5. IP Fragementation and Reassembly

Segment oversized IPv4 packets into several packets of max size, even those with the DF-bit set. Optionally re-assemble the segments into the original packet, for instances where the application does not support reassembly.  

```bash
#Segment packets up to 9000 bytes into 1400 byte segments when received on eth0
bpfc -i eth0 -d ingress -p 100 "ip-frag 1400 9000;"

#Re-assmble fragmented packets when sending to eth0
bpfc -i eth0 -d egress -p 100 "ip-defrag"
```

Note: The `ip-frag <size> <max>` and `ip-defrag` commands will automatically install matching criteria for IPv4 packets, but will ignore the DF bit by design. If it is desired to not fragment packets with the DF-bit set, use `match ip-ndf` before `ip-frag` to only match packets without the DF-bit set.

When performing an `ip-defrag` the maximum reassembled size is limited by the interface MTU. When forwarding, it is recommended to attach the `ip-frag` to ingress and `ip-defrag` to egress.  When operating as the end host, do the opposite with `ip-frag` on the egress and `ip-defrag` on the ingress.   
