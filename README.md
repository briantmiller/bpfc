# Programmable eBPF Network Fabric Compiler & Dataplane

A standalone, LLVM/Clang-independent eBPF assembler and dataplane written in pure C with zero library dependencies. This tool parses a custom, semicolon-separated instruction set to generate raw eBPF bytecode, load/verify into the kernel, and bind it to network interfaces via raw Netlink TC `clsact` queuing disciplines.

Designed to be a deployable eBPF dataplane and networking swiss army knife.  Useful for Red Team operations, SD-WAN edge routing, and high-performance network programming, it supports dynamic variables, stateful map sharing, nested branching logic, and on-the-fly L2-L4 encapsulation.

---

## Requirements
* Linux kernel 4.18+ (Includes native RHEL 8 / CentOS 8 verifier compatability)
* Root privileges (`CAP_NET_ADMIN` / `CAP_SYS_ADMIN`)
* XDP programs (`-d xdp`): kernel 5.18+ or RHEL 9.2+

---

## Usage & CLI Flags

```bash
# Install to an interface
sudo ./bpfc -i <interface> [-d ingress|egress] [-p <priority>] [-m <map_dir>] [-v] "<instructions>"

# Clean / Detach from an interface
sudo ./bpfc -i <interface> -c

# XDP: the interface's XDP program (generic mode), and removing it
sudo ./bpfc -i <interface> -d xdp "match udp; match udp-dst 9; drop"
sudo ./bpfc -i <interface> -d xdp -D
```

| Flag | Description |
| :--- | :--- |
| `-i <iface>` | Target network interface (e.g., `eth0`). If omitted, compiles to `output.bpf` locally. |
| `-d <dir>` | Hook direction: `ingress` (default), `egress`, or `xdp` (see [XDP](#xdp)). |
| `-p <prio>` | TC filter execution priority (e.g., `1`). Allows multiple stacked programs to execute sequentially. Re-running with the same priority replaces the program atomically. |
| `-m <dir>` | Path to store pinned eBPF maps (e.g., `/sys/fs/bpf/my_ns/`). Crucial for network namespaces. |
| `-f <file>` | Read instructions from a file (`-` for stdin). `#` comments run to the end of the line. |
| `-c` | Cleanup mode. Atomically deletes the `clsact` qdisc, detaching all filters from the interface. With `-d xdp`: removes the XDP program. |
| `-D` | Delete only the program at `-p <prio>` on `-d <dir>` (`-d xdp`: the XDP program, no `-p`). |
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
/etc/bpfc/interfaces.d/%all%/{ingress,egress}/<priority>.bpfc      every interface
/etc/bpfc/interfaces.d/%<kind>%/{ingress,egress}/<priority>.bpfc   every interface of that kind
/etc/bpfc/interfaces.d/{<interface>,%all%,%<kind>%}/xdp.bpfc       the interface's XDP program
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
* **All interfaces, or all of a kind**: `%all%/` applies to every interface; `%<kind>%/` to every interface of that kind as `ip -d link` shows it (`%veth%`, `%gre%`, `%vxlan%`, `%wireguard%`, `%tun%`, ...), `%nic%` to devices without a kind (physical NICs) and `%lo%` to loopback. On devices without an Ethernet header (gre, ipip, sit, wireguard, tun) packets start with the IP header and bpfc reads the IP fields there (see `$L3OFF`); a template that uses Ethernet fields (MACs, VLAN, ARP, MPLS) fails to compile on them (status `failed`, the other interfaces still get it), so guard that part with `when $L3OFF == 14` or put an empty file for that priority in `%gre%/`, `%wireguard%/`, ... For each direction and priority the most specific file wins: `<interface>/`, then `%<kind>%/`, then `%all%/`; other priorities still apply. An empty file (only comments) at a more specific level means nothing at that priority there: `eth1/ingress/100.bpfc` empty exempts eth1 from `%all%/ingress/100.bpfc` (status `excluded`). New interfaces get the programs when they appear; a template is compiled once per interface, with `$IFNAME`, `$IFINDEX`, `$IFTYPE` and `$IFKIND` set for it. Programs on stacked devices (a bridge and its ports, a bond and its slaves) see the same packet more than once. Only the default network namespace is managed.
* **tc ingress runs after GRO**: a filter here covers bugs in TCP/IP processing, not in GRO or the driver; for those use `xdp.bpfc`.
* **XDP**: `xdp.bpfc` in an interface's (or template's) directory is its XDP program, attached in generic mode, one per interface (no priority; `bpfcctl show eth0 xdp`). Templates, empty files, reloads, failures, adoption and external changes work as for TC. It runs before TC ingress.
* **External changes**: if something else removes or replaces a managed program, bpfcd reinstalls it or only logs it, per `on_external_change` in `/etc/bpfc/bpfc.conf`.
* **Tracking**: each program's id and tag are recorded with its file path and hash in `/run/bpfc/state`; filters are named `bpfcd:<iface>/<dir>/<prio>`.
* **Network namespaces**: `bpfcd -n <name>` (usually `systemctl enable --now bpfcd-netns@<name>`) manages namespace `<name>` from `/etc/bpfc/netns/<name>/` (`bpfc.conf`, `interfaces.d/`), with its own state (`/run/bpfc/netns/<name>`) and pinned maps (`/sys/fs/bpf/netns/<name>`). The namespace is `/run/netns/<name>`, or `netns_path` (a namespace file or a symlink to one, re-followed every second), or `netns_veth` (the namespace holding the peer of a host-side veth: a pod or container). bpfcd waits for a namespace that is not there yet, moves its programs when the path or veth comes to point at another namespace, and lets a deleted one be freed. `bpfcctl -n <name>`, `bpfcctl --all-netns` and the `-n` option of the bpfc-scripts tools work on it; `bpfcctl -n <name> exec <command>` runs a command inside it.

* **REST API** (off by default): with `rest_socket = /run/bpfc/bpfcd.sock` in `bpfc.conf`, bpfcd serves HTTP on that unix socket (owner `root:bpfc`, mode `0660`: add users to the `bpfc` group; whoever can connect can change programs). `GET /` is the status as JSON; `GET /interfaces/<if>` one interface; `/interfaces/<if>/<ingress|egress>/<prio>` (and `/interfaces/<if>/xdp`) is a program file as a JSON array of lines: `GET` reads it, `POST`/`PUT` writes and installs it, `DELETE` removes it. Writes are checked with `bpfc -T` first and rolled back if installing fails; `?dry-run` only checks. Written files live in `/var/lib/bpfc/interfaces.d` and override the same file in `/etc/bpfc/interfaces.d`. `bpfcctl status --json` prints the same status locally.

```bash
curl --unix-socket /run/bpfc/bpfcd.sock http://localhost/interfaces/eth0
curl --unix-socket /run/bpfc/bpfcd.sock -X POST -d '["match tcp;", "  match tcp-dst 23;", "    drop"]' \
     http://localhost/interfaces/eth0/ingress/10
curl --unix-socket /run/bpfc/bpfcd.sock -X DELETE http://localhost/interfaces/eth0/ingress/10
```

```bash
mkdir -p /etc/bpfc/netns/pod1/interfaces.d/eth0/ingress
echo 'netns_veth = veth3f2a1c' > /etc/bpfc/netns/pod1/bpfc.conf   # the pod's host-side veth
cp drop-telnet.bpfc /etc/bpfc/netns/pod1/interfaces.d/eth0/ingress/100.bpfc
systemctl enable --now bpfcd-netns@pod1
bpfcctl -n pod1
```

See `bpfcd(8)`, `bpfcctl(8)` and `bpfc.conf(5)`. Build an RPM (RHEL 9/10) with `make rpm`; run the daemon's integration and container tests with `make check` (root).

---

## XDP

`-d xdp` compiles the same language into an XDP program and attaches it as the interface's XDP program, in generic (skb) mode for now (native/driver mode later). It runs before GRO, TC and the stack. One program per interface; attaching replaces it atomically.

* `accept` and `continue` pass the packet on (XDP_PASS), `drop` is XDP_DROP, `redirect <iface>` sends it out of that interface, and `tx` (XDP only) sends it back out of the interface it came in on.
* Checksum-aware rewrites (`set ip-src`, ports, `ip-tos`, ...) update the IP and TCP/UDP checksums incrementally, as on TC. XDP sees complete checksums; a packet a local socket sent through a veth pair may carry a partial one (CHECKSUM_PARTIAL), which an L4 rewrite corrupts once the packet is forwarded: turn tx checksum offload off on such senders (`ethtool -K <dev> tx off`).
* VLAN tags are in the packet: `match vlan`/`qinq`, `get`/`match vlan-id` read them there, `set vlan-id` rewrites the id in the tag (keeping priority and DEI; pushes an 802.1Q tag when there is none), and `push-`/`pop-vlan` insert or remove the 4-byte tag after the MAC addresses. A NIC that strips tags (`rxvlan` offload) may hand generic XDP packets without them.
* Resizing works: `add-head-bytes`, `add-bytes`/`del-bytes`, `add-l2-bytes`/`del-l2-bytes`, `push-`/`pop-eth`, `push-`/`pop-vlan`, `push-qinq`, `encap-`/`decap-mpls`, `encap-`/`decap-gre`, `insert-l2`/`remove-l2`/`strip-l2` and `set len`, so the [MPLS pseudowire](#3-mpls-pseudowires) examples run as XDP programs too. The packet grows or shrinks at the front with `bpf_xdp_adjust_head` (up to 255 bytes at a time; generic mode has 256 bytes of headroom) and at the end with `bpf_xdp_adjust_tail`; inserted bytes are zero, as on TC. Growing at the end needs tailroom, which generic mode may not have.
* Commands that need an skb are a compile error naming the command: `ip-frag`, `ip-defrag`, `clone`, `redirect-neigh`, `reclassify`, and the skb fields (`skb-mark`, `skb-hash`, `skb-cb`, `protocol`, `tstamp`, `set queue`). `get len`, `skb-ingress`/`skb-ifindex` (the ingress interface) and `queue` (the receive queue) work.
* `$XDP` (1 in an XDP program) and `$HOOK` (`ingress`, `egress`, `xdp`) let one file serve several hooks: `when $XDP == 0; set skb-mark 5; end-when`.

---

## Tests

**Tests.** `./test.sh` runs every suite (root; about an hour) and ends with pass/fail/skip totals per suite; it exits non-zero if anything failed. Name suites to run only those (`./test.sh bpfc nat`), add `-f` to print failures only, or `-v` for each suite's full output; logs are kept under `/tmp/bpfc-tests.*`. `make check` (compile, preprocessor, stack, bpfcd, xdp, container, install), `make check-dataplane` (the dataplane suites and the verifier budget) and `make check-all` use the same runner; the `verifier-budget` suite loads every generated dataplane program (each profile, and the extremes of the structural settings) and fails if one uses more than `BUDGET_PCT` percent (default 85) of the verifier's 1,000,000-instruction limit (kernel 5.16+; it skips on older kernels); `make check-compile` needs no root and checks that every field and command compiles, that hex and decimal values give the same code, and that invalid programs are refused with a clear message; the `install` suite checks what `make install` and, when `rpmbuild` is present, the RPMs put where (binaries in bpfc; dataplane tools, every built-in profile and docs in bpfc-scripts) and runs the installed generator against the installed profiles; pass flags with `make check TESTFLAGS=-f`. Suites skip (rather than fail) when they are not run as root or need something the system lacks: a tool (tcpdump, ncat, iperf), kernel MPLS routing (`mpls_router`), or scapy for `tests/test_bpfc.py`. The fragmentation suites check each fragment size with three ordinary pings and, separately, the loss under load (100 parallel pings), which must stay below `STRESS_MAX_LOSS` hundredths of a percent (default 100, i.e. 1 %). New shell suites should `source tests/lib.sh` for `test_pass`/`test_fail`/`test_skip`, `check` and `tests_exit`.

---

## Container integration

**Containers (no systemd):** the `bpfc-container` package adds `/usr/sbin/bpfcd-entrypoint`, which runs bpfcd as the container's PID 1. Neither package requires systemd, and settings can be passed as `BPFCD_*` environment variables. See [dist/container/README.md](dist/container/README.md) for an example Containerfile and run options. `make rpm RPMBUILD_OPTS="--with static"` builds statically linked binaries for images without a matching libc.

---

## Dataplane: FEC, ARQ, in-band telemetry and bandwidth probing

`dataplane/bpfc-dataplane-gen` generates bpfc programs for a point-to-point link (both ends run them): every IPv4 packet gets an 8-byte shim with a sequence number and timestamp, after the Ethernet header (EtherType 0x88B5) on a Layer-2 link, or inside UDP (`--carrier udp`: an outer IPv4/UDP header to the peer, for routed paths, the internet and NAT; `--carrier udp-inline`: UDP after the packet's own IP header, for a private routed WAN) for the remote prefixes given with `--protect`. The receiver measures loss, reordering, duplicates, jitter and queueing delay (no clock synchronisation needed) and reports back once a second. When loss crosses a threshold the sender adds XOR parity (forward error correction), scaled to the loss, and turns it off again after a cool-down; lost packets are also retransmitted from a short buffer (ARQ), and packet-pair probes estimate the link capacity (probe trains and a median on links that deliver in frames, such as Starlink: `--probe-train 20ms --capacity-percentile 50`, set in the `leo` profile). Each interface has its own maps.

Both come in the optional `bpfc-scripts` package (`dnf install bpfc-scripts`; `make install` installs it too, or `make install-scripts` alone): `bpfc-dataplane-gen` and `bpfc-dataplane-status` in `/usr/sbin`, the built-in profiles in `/usr/share/bpfc/dataplane/profiles/`, and DESIGN.md with example programs in `/usr/share/doc/bpfc-scripts/dataplane/`. Both tools are bash scripts; from a source tree they also run in place (`dataplane/bpfc-dataplane-gen` finds `dataplane/profiles/` next to it).

Profiles set the defaults for a kind of link (`direct`, `wan`, `geo`, `leo` built in; your own in `/etc/bpfc/dataplane/profiles.d/`), and `--link-rate` / `--rtt` size the retransmit ring and windows.

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

See [dataplane/DESIGN.md](dataplane/DESIGN.md) for the wire format, the algorithms and the limits; `make check-dataplane` (root) runs its end-to-end tests (`dataplane`, `dataplane-udp`, `verifier-budget`).

### Bandwidth-aware ECMP (`bpfc-ecmp-gen`)

A routing layer on a single router: it balances flows over the next hops of the kernel's multipath routes by measured load, with interface preferences per traffic class. It needs nothing from its neighbours and is independent of the FEC dataplane. Packets change only as in any router (TTL, IP checksum, MACs). IPv4.

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

Every packet re-checks that its flow's interface is still a member of the route, so a withdrawn next hop is noticed on the next packet. See [ecmp/DESIGN.md](ecmp/DESIGN.md); `make check-ecmp` (root) runs the end-to-end tests.

---

## Language Syntax

Instructions are strictly **semicolon-separated**. Variables (denoted by `%`) are dynamically allocated on the 512-byte eBPF stack and natively converted to Host Byte Order for mathematical operations.

### Variables
* `decl <VAR> <size>` - Create a new variable of `<size>` bytes (1, 2, 4, 8 or 16). A 16-byte variable holds an IPv6 address in network byte order, for `get`, `set` and `match` of `ip6-src`/`ip6-dst`.
* `set val <VAR> <%VAR | int>` - Set variable to integer value or value from another variable
* `free <VAR>` - Free `VAR` from the stack, making space available for later variables.  

**Stack layout.** The 512-byte stack holds 128 bytes of fixed scratch used inside single instructions, then one 8-byte slot per variable (two for a 16-byte one), as many as the program declares, up to 48 slots. Instructions that need more scratch (`fib-lookup`: 72 bytes, `push-eth`: 32, the byte-insertion and deletion commands) take it below the variables and give it back when they finish. `xor-packet` and the TCP/UDP checksums stage packet data in chunks of up to 256 bytes: with more than 16 variables the chunks get smaller (down to 8 and 4 bytes), which works the same but costs more verifier instructions. The variables `fib-lookup` adds (`FIB_RESULT`, `FIB_SMAC`, `FIB_DMAC`, `FIB_IP_DST`, `FIB_IFINDEX`) count as five. If something does not fit, bpfc says which instruction needs how much; `free` variables you no longer need.

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
Fields support extraction (`get <field> <VAR>`), assignment (`set <field> <val | %VAR>`), and evaluation (`match <field> <val | %VAR>`). Subnets (`10.0.0.0/24`) and port ranges (`80-100`) are fully supported. Numbers may be decimal or `0x` hex anywhere. Values are checked when compiling: a number must fit the field (port 0-65535, `ip-tos` 0-255, `vlan-id` 0-4095, ...), addresses must be complete (`10.0.0.300`, `10.0.0` or a 5-byte MAC are errors), and a range must be low-high; `redirect`/`clone` to an interface that does not exist is an error too. Variables hold host-order values, so `match <field> %VAR` compares with what `get <field>` stored (for `mpls-label`, the label itself). `match vlan` / `match qinq` look at the offloaded tag, or at the frame when no tag is offloaded.

* **L2:** `dst-mac`, `src-mac`, `eth-proto`, `vlan-id` (`set vlan-id` replaces the id of the tag and keeps its priority and TPID; without a tag it adds an 802.1Q one)
* **IPv4:** `ip-src`, `ip-dst`, `ip-tos`, `ip-proto` (`set ip-src`/`ip-dst` update the IP checksum and the TCP/UDP checksum, whose pseudo-header covers the addresses; a UDP checksum of 0 stays 0)
* **IPv6:** `ip6-src`, `ip6-dst`, `ip6-tclass`, `ip6-flow`, `ip6-proto`
* **L4:** `tcp-src`, `tcp-dst`, `udp-src`, `udp-dst`, and `match tcp-flags`, `icmp-type`. These follow the real IPv4 header length (IHL), so packets with IP options are read and rewritten at the right place (they used to be read at fixed offsets that assume a 20-byte header). They are IPv4 fields: on another packet a match does not match, `get` stores 0 and `set` changes nothing.
* **ARP:** `arp-htype`, `arp-ptype`, `arp-hlen`, `arp-plen`, `arp-oper`, `arp-sha`, `arp-tha`, `arp-spa`, `arp-tpa`
* **MPLS:** `mpls-label`, `mpls-bos`
* **GRE:** `gre-key`, `gre-proto` (any IHL; the key is found after the checksum when the C bit is set)
* **TCP (IPv4, any IHL; `get` only):** `tcp-seq`, `tcp-ack`, `tcp-flags` (the flags byte: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10), `tcp-win` (unscaled), `tcp-hlen` (header length incl. options, bytes). 0 when the packet is not IPv4 TCP.
* **Offsets and lengths (IPv4, any IHL; `get` only):** `l4-off` (offset of the TCP/UDP/... header in the frame), `payload-off` (TCP: after the options, UDP: after 8 bytes), `payload-len` (from the IP total length, so Ethernet padding is not counted). Use them with variable offsets: `get bytes %OFF 4 V`.
* **Flow key (`get` only):** `flow-key [reverse | symmetric]` - 64-bit hash of the IPv4 addresses, protocol and TCP/UDP ports (never 0; 0 for non-IPv4). `reverse` is the key of the opposite direction, so a returning ACK finds its data flow's map entry; `symmetric` is the same key for both directions.
* **Generic:** `bytes <offset | %VAR> <length>` - with a variable offset the bytes are read with `bpf_skb_load_bytes` (0 if outside the packet) and written with `bpf_skb_store_bytes` (nothing written if outside).

### Context Metadata (`__sk_buff`)
* `len` - Packet length (`u32`).
* `protocol` - Protocol stored in sk_buff, as an EtherType (`match protocol 0x0800`; `get` stores it in host order).
* `skb-ifindex` - Interface number associated with sk_buff.
* `dev-type` (get/match), `dev-kind` (match) - The device type (`skb->dev->type`, ARPHRD: 1 Ethernet, 772 loopback, 778 GRE, 768 IPIP, 65534 none, e.g. wireguard and tun) and kind (`veth`, `gre`, `vxlan`, ...; `nic` without a kind, `lo`) of the `-i` interface. They are looked up when compiling (TC programs cannot read `skb->dev`), so a match costs no instructions: it is always true, or its block is never entered. Without `-i`, pass `-s IFTYPE=<n> -s IFKIND=<kind>`.
* `skb-ingress` - Ingress interface number associated with sk_buff.
* `skb-mark` - Netfilter/iptables firewall mark (`u32`).
* `skb-hash` - RPS flow hash (`u32`).
* `tstamp` - `skb->tstamp`, 64-bit ns. On egress, a time in the future (CLOCK_MONOTONIC, as `get time`) holds the packet until then under the fq qdisc (earliest-departure-time pacing).
* `skb-cb <0-4>` - 20-byte control buffer array (5x `u32` slots) for passing state across tail-calls and to the next TC priority.
* `cpu` - (`get` only) number of the CPU running the program.
* `time` - (`get` only) CLOCK_MONOTONIC in ns (`bpf_ktime_get_ns`), into an 8-byte variable.
* `random` - (`get` only) a pseudo-random 32-bit number (`bpf_get_prandom_u32`).
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
* `fib-lookup [options] [<address> | %VAR]` / `fib-lookup6 ...` - Queries the kernel's routing tables (`bpf_fib_lookup`), for the packet's destination unless an address is given. Populates `%FIB_RESULT`, `%FIB_SMAC`, `%FIB_DMAC`, `%FIB_IP_DST`, `%FIB_IP6_DST`, `%FIB_IFINDEX`. The address can be a 4-byte variable in host order, as `get ip-dst` gives it (`get ip-dst D; fib-lookup %D`); `%FIB_IP_DST` comes back in the same order. Options:
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
* `push-eth <d_mac> <s_mac>` / `pop-eth` - `pop-eth` removes the outer Ethernet header, leaving the inner one (IP packets).

### Structural Manipulation & Checksums
* `add-bytes <offset> <len>` / `del-bytes <offset> <len>` - Inserts `<len>` number of bytes at `<offset>` and shifts packet tail down/up.
* `add-head-bytes <len>` - Adds bytes to head of packet.
* `del-bytes <offset> <len>` - Delete bytes at specific offset. Will attempt to use buffer maps if available, then revert to unrolled loop if necessary.
* `add-l2-bytes <len>` / `del-l2-bytes <len>` - Insert or remove `<len>` bytes right after the Ethernet header (offset 14), for any protocol; the same as `add-bytes 14 <len>` / `del-bytes 14 <len>`. For IPv4/IPv6 packets `insert-l2` / `strip-l2` are cheaper.
* `insert-l2 <len> [ethertype]` - Insert `len` zero bytes after the Ethernet header (IPv4/IPv6 packets) and optionally set the EtherType. Headers behind it keep their place in memory, so checksum offload keeps working.
* `remove-l2 <len> [ethertype]` - The counterpart of `insert-l2`: remove `len` bytes (1-64) after the Ethernet header of an IPv4/IPv6 packet and optionally set the EtherType. skb->protocol stays IPv4/IPv6 (`strip-l2` changes it), so the packet can be grown again with `insert-l2` later.
* `strip-l2 <len> <ethertype>` - Remove `len` bytes (multiple of 4) after the Ethernet header and set the EtherType, for any protocol (`bpf_skb_adjust_room` refuses non-IP packets). No payload copy; the stack sees the new protocol directly.
* `recalc-tcp-csum [l3 [max]]`, `recalc-udp-csum [l3 [max]]` - L4 checksum recomputed from scratch via `bpf_csum_diff`: any IHL, length from the IP header, packets up to `max` bytes (default 9000). On egress, locally sent TCP/UDP packets usually still have checksum offload pending (the kernel or NIC completes the checksum after the program), so recalculate on ingress or for forwarded packets.
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
* `when <expr>` ... [`otherwise` ...] `end-when` - Keep one branch, decided at compile time. `defined(NAME)` tests for a const; `when <word> == <word>` (or `!=`) compares text when a side is not a number, e.g. `when $IFKIND == gre`.
* `$IFNAME`, `$IFINDEX`, `$IFTYPE`, `$IFKIND`, `$IFMAC` - The `-i` interface's name, index, device type (ARPHRD), kind (as for `dev-kind`) and MAC address, so one file can serve many interfaces (bpfcd's `%all%`): `set map CNT_$IFNAME 1 1`. `-s` overrides them.
* `$L3OFF` - Where the IP header starts: 14 behind an Ethernet header, 0 on devices whose packets start with it (device types none, GRE, IP6GRE, IPIP, IPv6 tunnel, SIT, raw IP, PPP: tun, wireguard, gre, ipip, sit, ...). bpfc reads every IP and L4 field from there by itself; `match ip`/`ip6`/`tcp`/... check the IP version instead of the EtherType; Ethernet fields and commands (MACs, `eth-proto`, VLAN, ARP, MPLS, push/pop-eth, encap/decap, strip/insert-l2, fib-lookup, ip-frag) are an error. Raw offsets (`get bytes`, `add-bytes`, `xor-packet`, ...) are frame offsets, so write them as `$(L3OFF + 9)` in a program for both kinds of device. Set by `-i`, or `-s L3OFF=0`.
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

The same programs work as XDP programs: use `-d xdp` instead of `-d ingress` (`./test.sh mpls-xdp` runs the pseudowire test that way).

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

The examples below use the preprocessor (`const`, `define`, `include`, `repeat`, `when`, `$IFNAME`/`$IFINDEX`/`$IFMAC`/`$HOOK`) for common network problems: 6–12 are XDP programs (the earliest hook, for forwarding and filtering at line rate), 13–18 TC programs (both directions, and the kernel's skb metadata: marks for policy routing, departure times for pacing, clones for mirroring). They are installed in `/usr/share/doc/bpfc/examples/{xdp,tc}/` (`dist/examples/` in the source), and `tests/test-xdp-examples.sh` and `tests/test-tc-examples.sh` run each of them as it is. Attach one with `bpfc -i <iface> -d xdp -f <file>` (or `-d ingress|egress -p <prio>`), or let bpfcd do it: copy it to `/etc/bpfc/interfaces.d/<iface>/xdp.bpfc` or `.../<iface>/{ingress,egress}/<prio>.bpfc` (or `%all%/`, `%nic%/`, ... for every interface; `$IFNAME`, `$IFINDEX` and `$IFMAC` are then each interface's own). Constants can be changed without editing the file: `-s MSS=1400`.

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
