# FEC / INT / ARQ / probing dataplane for bpfc

A dataplane for a point-to-point link, written as bpfc programs. Both ends
run the same programs, and each end is the sender for its own direction.
Every IPv4 packet sent on the link carries an 8-byte shim with a sequence
number and a timestamp: after the Ethernet header (EtherType 0x88B5) on a
Layer-2 link, or inside UDP across a routed path, the internet or NAT (see
[Carriers](#carriers)). The receiver measures the link and reports back, and
the sender adapts:

- **INT (in-band telemetry).** The receiver measures loss, reordering,
  duplicates, jitter and queueing delay. No clock synchronisation is needed.
  It reports to the sender once per report interval (1 s by default), and the
  sender works out the RTT from the report.
- **FEC.** XOR parity: one parity packet per K data packets. It turns on when
  the reported loss reaches a threshold (1 %), and K scales with the loss.
  It turns off after the loss has stayed below the threshold for a cool-down
  period (10 s), or drops back to a configured floor that stays on.
- **ARQ.** The receiver NAKs gaps right away, and the sender retransmits
  from a ring of recent packets, sized from the link rate × RTT. While FEC is
  on, ARQ keeps going, answers only for the most recent packets, or stops.
- **Bandwidth probing.** Every 10 s (`probe-interval`, or `probe-rate`
  probes per second) the sender sends one packet twice back to back. The
  receiver turns the gap between the copies, and the bytes that arrived in
  it, into a capacity sample for that direction; the estimate is a high
  percentile of the last 16 samples, or of those taken in the last
  `capacity-window` (for links whose capacity changes on a schedule, such as
  a LEO terminal moving to another satellite). On links that deliver in
  frames (Starlink, cellular, DOCSIS) a pair reads far too fast, so
  `probe-train` sends a train instead and `capacity-percentile` takes the
  median ([Probe trains](#probe-trains)). Probes are sent less often
  (×6, `probe-backoff`) while FEC is on. The estimate,
  together with the queueing delay, tells loss caused by congestion apart
  from loss on the line. When the link is congested, FEC uses a fixed ratio
  instead of scaling up and adding more traffic.

Each interface has its own maps (`<prefix>_*`, see [Map names](#map-names)),
so several links run independently. Profiles (`direct`, `wan`, `geo`, `leo`, or your own) set the
defaults for a kind of link; see [Profiles and sizing](#profiles-and-sizing).

## Files

| File | |
|---|---|
| `bpfc-dataplane-gen` | Generates the programs for one interface into `/etc/bpfc/interfaces.d/<if>/` (bpfcd installs them) |
| `bpfc-dataplane-status` | Shows link quality and what FEC/ARQ/probing are doing; changes settings at runtime |
| `profiles/*.profile` | Built-in profiles (installed in `/usr/share/bpfc/dataplane/profiles/`) |
| `../tests/test-dataplane.sh` | End-to-end tests (network namespaces, an 800 ms link emulator, content checks; `make check-dataplane`) |
| `../tests/test-dataplane-udp.sh` | The UDP carriers: a routed path with carrier-grade NAT, and a private routed WAN |
| `../tests/link-emulator.py`, `../tests/udp-verify.py` | Test helpers: delayed link, datagrams with checked contents |

```
bpfc-dataplane-gen -i eth0 --profile geo [settings]   # see --help
bpfc-dataplane-gen --list-profiles
bpfc-dataplane-gen --show-profile geo --rtt 650ms     # effective settings and sizes
bpfc-dataplane-gen -i eth0 --setup-hints              # link settings, below
systemctl reload bpfcd
bpfc-dataplane-status [eth0 ...] [detail|json]       # or -d / -j; -1 for key=value lines
bpfc-dataplane-status set eth0 fec-threshold 2      # unset eth0 fec-threshold
```

The default output is a table, one row per interface, in the style of FRR's
`show ... neighbor`:

```
Codes: * - fixed FEC ratio, the link looks congested
       ! - the most parity still leaves loss (the link looks full)
       S - buffers too small for the measured RTT and rate (see detail)

Interface  Peer               State  Health    Out Loss  Out Left  In Loss  In Left  RTT    Out Cap  In Cap  Sending  FEC
wan1.100   9e:d0:51:82:ba:0f  Up     DEGRADED  3.53%     0.42%     4.06%    0.48%    712ms  20.3M    10.0M   8.0M     1:7
```

Loss is the average over the last `loss-smoothing` packets, Left what is
still lost after FEC and ARQ; Out is the interface's sending direction (as
the peer measured it), In the receiving one. The flags column appears only
when a row has a flag. `detail` (or `-d`) gives the full report per
interface; `json` (or `-j`) the same data as one JSON document,
`{"interfaces": {"<name>": {...}}}`, with FRR-style camelCase names and the
unit in the name (`lossBp`, `rttUsec`, `capacityKbps`, `lastReportMsec`).
`-1` prints the older key=value line per interface, unchanged.

Health, from the loss estimates (averages over `loss-smoothing` packets,
not single report windows) of both directions: **POOR** when 1 % or more
is still lost after FEC and ARQ; it stays POOR until that falls to half,
or for the FEC cool-down after it was last at 1 %. **DEGRADED** when the
loss on the link is at the FEC threshold or more but repair brings it
under 1 %; it stays DEGRADED until the loss falls to half the threshold or
the cool-down passes. **GOOD** otherwise. Status tools older than the loss
estimate (no `out_loss_window_bp` in `-1` output) judge single report
windows and swing between states on a steady lossy link.

## Carriers

`carrier` (structural) says how dataplane frames cross the link. Inside the
dataplane every frame is Ethernet + shim (+ the IP packet), whatever the
carrier: with a UDP carrier one more program at the end of egress (priority
N+40) wraps each frame in UDP, and one at the start of ingress (N-10)
unwraps it, so the other programs are the same for every carrier.

| Carrier | Frame | Overhead | For |
|---|---|---|---|
| `ethernet` (default) | Ethernet, 0x88B5 \| shim \| IP packet | 8 | one Layer-2 segment: cable, VLAN, L2 circuit |
| `udp` | Ethernet \| IPv4 us → peer \| UDP \| shim \| IP packet | 36 | routed paths, the internet, NAT (satellite terminals, CGNAT) |
| `udp-inline` | Ethernet \| the packet's IP header, protocol UDP \| UDP (source port 0xB500 + protocol) \| shim \| L4 | 16 (36 on parity, NAK, report) | a private routed WAN (MPLS L3VPN) where QoS and policy on the path should see the site addresses and TOS |

Settings:
- `protect` (required with UDP): the remote prefixes carried to the peer,
  comma-separated (`10.2.0.0/16,10.3.0.0/16`, or `0.0.0.0/0`). Other
  packets leave untouched: not sequenced, not counted. It also works with
  the Ethernet carrier.
- `udp-port` (47810): the port this end sends from and receives on. Nothing
  listens on it; the ingress program takes the packets before the stack.
- `peer` (udp): `IPv4[:port]`, or `learn`: the address and port are taken
  from the peer's packets (latest wins, so a NAT that moves the mapping is
  followed), only from `peer-learn-from` (default `0.0.0.0/0`). Use `learn`
  on the end that faces a peer behind NAT; that peer sets this end's
  public address. Runtime: `bpfc-dataplane-status set eth0 peer A.B.C.D[:port]`.
- `local-address` (udp): the outer source. `auto` (default) takes the
  interface's address when generating, then the address the peer's packets
  are sent to (behind NAT, the one the interface has, so a DHCP change
  heals once the peer sends).
- `keepalive` (udp, 25 s): when nothing went to the peer for this long, the
  next IPv4 packet leaving the interface (any packet, not only protected
  ones) is cloned into a 60-byte keepalive (shim type 6), so the NAT
  mapping in front of this end stays open. The peer drops it (after
  learning from it). A link with no traffic at all sends none: keep
  something flowing (`ping -i 15` to a protected address).
- `path-mtu` (1500): the largest IP packet the path carries. Packets larger
  than `path-mtu` - overhead (1492, or 1464 for both UDP carriers) go out unprotected; set
  `mtu lock` on the routes to the protected prefixes (`--setup-hints`
  prints them).

Receiving (udp): IPv4 without options, not a fragment, UDP to `udp-port`,
a valid shim type, from the peer (static) or `peer-learn-from` (learn);
anything else to the port is dropped and counted (`refused`). Sending: DF,
TTL 64, the DSCP of the packet carried (QoS on the path still applies), no
UDP checksum (the payload is checked end to end), Ethernet header from a
route lookup of the peer (`fib-lookup`). Before a learned peer is known,
protected packets go out unprotected (counted, `not sent`).

udp-inline keeps the packet's IP header (addresses, TOS, TTL, ID) as the
outer one with protocol UDP, and puts the original protocol in the UDP
source port (0xB500 + protocol; the destination port is `udp-port`), so the
path classifies on the real addresses and DSCP. The receiver delivers the
header as it arrived: TTL lowered by the routers, DSCP as the path left it
(remarking, ECN CE). Because those fields change on the way, FEC leaves them
out: both ends fold members into parity with TOS, TTL and header checksum
zeroed, a parity frame travels with the TOS and TTL of the packet it was
made from (so it is queued with its traffic), and a rebuilt packet gets the
parity frame's TOS and TTL as it arrived and a new header checksum (its
TCP/UDP checksum is still checked). IP options and fragments go out
unprotected. A firewall on the path must pass UDP to `udp-port` from source
ports 46336–46591. NAKs and reports carry the addresses of the last packet
received, swapped, and parity those of the last packet sent, so both ends
must be on the routed path between the sites. No NAT.

Netfilter runs before the egress programs: do not masquerade traffic to the
protected prefixes on the interface. On ingress the carrier program runs
before netfilter, so no firewall rule is needed for the port on this host
(one on the path must pass it).

## Link requirements

- **Both ends run the dataplane.** IPv4 frames that arrive without the shim
  are still delivered, but they are not protected or measured.
- **Frames grow by 8 bytes.** Keep the interface MTU at 1500 so the NIC
  carries and accepts 1514-byte frames, and give IP an MTU of 1492 on the
  routes through the link: `ip route ... mtu lock 1492`. If an IP packet is
  still larger, it is sent without the shim and counted as bypassed. It is
  not dropped.
  On a VLAN subinterface (`eth0.100`) it is simpler to set the VLAN's own
  MTU to 1492 and leave the parent at 1500: routing daemons then see 1492
  (set it on both ends, OSPF compares MTUs) and no route needs a lock.
- **One TCP segment per packet.** TC sees packets before segmentation, so
  a GSO "super-packet" can't be encapsulated. Set
  `ip link set dev eth0 gso_max_segs 1` and
  `ethtool -K eth0 tso off gso off gro off`. Packets forwarded into the link
  from other interfaces must not be GRO-merged either
  (`ethtool -K <lan-if> gro off`). Merged packets go out unprotected.
  Hosts or containers attached by veth hand their TSO/GSO super-packets to
  the router unchanged (GRO settings do not help there): turn TSO/GSO off
  on those hosts (`ethtool -K <if> tso off gso off`). Status counts such
  packets as "Unprotected ... too large to encapsulate".
- **No hard drops after the dataplane on egress.** The FEC program copies
  each packet into its parity block before the qdisc runs. If a later TC
  program drops the packet (`TC_ACT_SHOT`) or the qdisc drops it and reports
  `NET_XMIT_DROP` (tbf, pfifo, fq when full), the sending TCP is told the
  segment was never sent and keeps it as unsent data, but the peer can still
  rebuild it from parity and acknowledge it. Linux rejects an ACK for unsent
  data, and with one segment in flight after a timeout the connection can
  stall for good. Use fq_codel (the RHEL default), which reports its drops
  as congestion (`NET_XMIT_CN`) so TCP counts the segment as sent, or give
  any shaper enough queue that it does not drop. Loss on the wire is not
  affected.
- **Point-to-point Layer 2.** A cable, a VLAN, or an L2 circuit (EVPL, VPLS,
  pseudowire). EtherType 0x88B5 is IEEE "local experimental", so a router
  will not forward it.
- **VLANs.** Run the dataplane on the VLAN interface (`eth0.100`). An
  offloaded tag on the packet is kept.

## Programs

| Hook | Priority | Program | Does |
|---|---|---|---|
| egress | 100 | encapsulate | Sequence number, timestamp and shim; ARQ copy; hands over to 110 in `skb->cb` |
| egress | 110 | fec | Per-CPU FEC block, parity, packet-pair probes |
| ingress | 100 | control | Packet-pair samples. REPORT: stores what the peer measured, runs the FEC controller. NAK: retransmits |
| ingress | 110 | parity | Rebuilds a missing packet from parity |
| ingress | 120 | receiver | Sequence, duplicates, gaps, reordering, jitter, delay; hands over to 130 |
| ingress | 130 | deliver | Folds FEC members into their block, decapsulates, delivers; sends NAKs and reports |
| egress | 140 | carrier | UDP carriers only: wraps every dataplane frame in UDP |
| ingress | 90 | carrier | UDP carriers only: unwraps the peer's UDP, learns its address |

The work is split across priorities to keep each program well inside the
verifier's 1,000,000-instruction budget. On kernel 6.18 (`bpfc -I` prints
`verified=`) the largest uses about 125,000 for every profile and buffer
size: the duplicate-window clear is a loop, and one NAK asks for at most 32
packets, so the cost doesn't grow with the sizes. Only one program
touches a packet's state at each step. Programs pass state on through
`skb->cb` with a magic value. Frames the dataplane sends itself (clones,
NAKs, reports, retransmissions) re-enter egress, and the first program clears
the mark on them, so the FEC program ignores them.

## Profiles and sizing

A profile is a file of `name = value` lines using the generator's option
names. It may `inherit` from another profile (up to 8 levels; loops are an
error), and an unknown name or invalid value is an error with file and line.
Settings are applied in order: built-in defaults, the profile chain (parents
first), then the command line.

Profiles are found in `--profile-dir`, then `/etc/bpfc/dataplane/profiles.d/`,
then `/usr/share/bpfc/dataplane/profiles/`, then `profiles/` next to the
generator. A file in `/etc` with a built-in's name replaces it.
`--save-profile NAME` writes the `--profile` used plus the settings given on
the command line as a new profile. The generated programs record the profile
and every effective value in their header, and the status script shows them.

| Profile | Rate / RTT | Settings |
|---|---|---|
| `direct` | 1 Gbit/s, 1 ms | FEC on at 1 % loss, ARQ for the last 3 packets while FEC is on |
| `wan` | 1 Gbit/s, 30 ms | FEC on at 1 %, ARQ for the last 50 ms while FEC is on |
| `geo` | 20 Mbit/s, 800 ms | FEC always on, at least 1:15, up to 1:4; ARQ answers everything it holds; reports every 500 ms; congestion delay 150 ms |
| `leo` | 100 Mbit/s, 60 ms | FEC on at 1 %, off after 30 s; reports every 250 ms; congestion delay 50 ms; 20 ms probe trains (up to 256 packets, timed from 10 % in) every 3 s, not slowed while FEC is on; capacity the median of the last 15 s of samples (a satellite handover about every 15 s) |

Carrier, interleaving and DSCP-aware ARQ (from the profile discussion) are
not built yet; the profiles use the L2 carrier for now.

**Sizing.** `link-rate` and `rtt` together give packets per second
(`sizing-packet-bytes`, default 1000, is the assumed average packet). From that:

| Buffer | Size | Range |
|---|---|---|
| ARQ ring | rate × RTT × 1.5 | 10 – 16,384 |
| Duplicate window | rate × (2 × RTT + 100 ms), rounded up to a power of two × 64 | 1,024 – 16,384 |
| FEC receive slots | 4 per CPU, power of two (blocks in progress depend on sending CPUs, not on rate) | 16 – 64 |

Without `link-rate` and `rtt` the old fixed sizes apply (ring 10, window
1,024, 16 slots). Each can also be set directly.

The generator warns when a buffer hits its cap, and when 16-bit sequence
numbers can't cover 2 × RTT + 100 ms: at 1 Gbit/s and 30 ms they can't, which
is what the larger shim classes are for. `--show-profile` also prints how long
the sequence space lasts; an outage longer than that is counted as a resync,
not as loss.

`bpfc-dataplane-status` compares the measured RTT and send rate with these
sizes and prints a `Sizing WARNING` with the options to regenerate with when
the ring or window is too small.

Settings marked `[runtime]` in `--show-profile` can also be changed on a
running link (`bpfc-dataplane-status set`); buffer sizes need regenerating.

## Wire format

Ethernet header, EtherType **0x88B5**, then 8 bytes (big-endian, shown as a 64-bit word):

```
DATA / RETX   type:3 flags:5 | k:4 idx:4 | seq:16 | block:8 | ts:24        then the IPv4 packet
PARITY        type:3 flags:5 | 0:4 n:4   | saved:16 | block:8 | code:8 | seq_xor:16  then the parity bytes
NAK           type:3 flags:5 | count:8   | first_seq:16 | 0:24
REPORT        type:3 0:5     | 0 ...                                       then 11 x 8-byte values
```

- **type:** 1 DATA, 2 PARITY, 3 RETX (retransmission), 4 NAK, 5 REPORT, 6 KEEPALIVE (carrier udp)
- **flags:**
  - 0x10: member of FEC block `block`, index `idx`, block size `k`
  - 0x08 / 0x04: probe copy 1 / 2 (head and tail of a train); both: a
    train filler, whose `ts` field carries `S << 12 | index` (S: the index
    the receiver starts timing at)
  - 0x02: the sender has FEC on
  - 0x01: the sequence restarted (first 1024 packets after the maps were created)
- **ts:** the sender's monotonic clock in 4 µs units, modulo 2^24 (it wraps after 67 s).
- **seq:** 16 bits on the wire. The receiver extends it to 64 bits around the
  highest sequence seen.
- **Parity `saved` / `code`:** the parity frame is made from a packet that may
  still carry a partial TCP/UDP checksum (checksum offload). The kernel or
  NIC then writes that checksum into the parity bytes at the original
  checksum position. The sender saves the real 2 bytes in the header, and the
  receiver puts them back. `code` is 0 (none), 1 (UDP, IP offset 26) or
  2 (TCP, IP offset 36).
- **REPORT values (8 bytes each, from offset 22):**
  1. packets received
  2. loss, as `residual_bp << 32 | raw_bp` (basis points)
  3. jitter (µs)
  4. queueing delay (µs)
  5. echo, as `1 << 63 | ts24 << 32 | held_us`
  6. capacity (kbit/s)
  7. `duplicates << 32 | reordered`
  8. `fec_rebuilt << 32 | arq_recovered`
  9. residual lost (total)
  10. gaps (total)
  11. packets expected this window

Overhead: 8 bytes per packet (36 or 20 with a UDP carrier), plus parity (1/K of the packets while FEC is
on), plus one 110-byte report per second per direction while traffic flows,
plus 60-byte NAKs.

## Sender

**Encapsulate (egress 100).** Builds the shim with `insert-l2 8 0x88B5`
(`bpf_skb_adjust_room`). The IP and TCP headers keep their place in memory,
so checksum offload is unaffected. It then stores shim + packet in ARQ ring
slot `seq % depth` and writes the tag `seq << 16 | length`.

**FEC (egress 110).** Blocks are per CPU. Several CPUs transmit at the same
time, and a shared block would need locking. Each CPU's state is one 64-bit
word in `_pcpu`:

```
open:1 | k:4 | idx:4 | block:8 | length_or:12 | seq_xor:16
```

The accumulator is a per-CPU buffer. Block ids come from an atomic counter
(`calc-map`), so blocks from different CPUs never clash.

Members are IPv4 with IHL 5 and not SCTP. Each member is XORed into the
accumulator (`xor-packet`). For TCP/UDP, the checksum folded in is the one
the packet *will* carry, computed with `calc-csum`, not the partial value
that may be in the field at this point. A rebuilt packet therefore carries
its real checksum, and the receiving kernel verifies it.

When `idx` reaches `k`:
1. The packet is cloned out.
2. The original becomes the parity frame. Its length is the OR of the member
   lengths (an upper bound on the longest), and its bytes are the
   accumulator.
3. XORing the parity back clears the accumulator.

A block that is still open after 50 ms (`fec-timeout`), or when FEC turns
off, is sent early: the next packet carries its parity, with `n` = members
so far. K never changes inside a block.

**Probes.** If the probe interval has passed and the packet is at least 600
bytes, the packet is cloned with flag probe 1 and the original follows with
probe 2. The interval is multiplied by the backoff while FEC is on.
`probe-rate N` sets the interval to 1/N s (0.00002–100 per second, so
10 ms at most often); each probe duplicates one packet, e.g. 10 probes/s of
1500 bytes add 120 kbit/s.

Each direction is measured by its receiver and reported back, so an
asymmetric link shows two different capacities: status lists the
outbound one (measured by the peer) and the inbound one (measured here).

**Controller (ingress 100, on each REPORT).** Records the peer's
measurements and the RTT (now − echoed ts − time the peer held it). It
updates the loss estimate (below) and
computes the send rate, the utilisation (`rate / capacity`) and congestion:
the link counts as congested when utilisation ≥ 85 % or queueing delay
≥ 20 ms, or when repair is failing: FEC already sends its most parity
(`fec-k-min`) and the loss left after FEC and ARQ is still at or above
the FEC threshold. More parity cannot fix that, and on a full link it adds
to the loss it repairs (an overloaded 10 Mbit/s link went to 20 % loss with
1:4 parity). The repair-failing state (`_tx` 50) holds until the loss left
falls below half the threshold or the loss below the threshold, because the
lighter fixed ratio would otherwise end it at the next report.

| Condition | K |
|---|---|
| loss ≥ threshold, congested | `fec-k` (8), fixed |
| loss ≥ threshold, not congested | `2500 / loss_bp` (1 / (4 · loss)), clamped to [`fec-k-min`, `fec-k-max`] = [2, 15] |
| loss < threshold for `fec-cooldown` | 0 (off) |

**Loss estimate.** A report covers the packets since the last one, which
can be a handful on a quiet link: one loss in three packets reads as 33 %.
The controller (and status) therefore use an average over the last
`loss-smoothing` packets (2000), weighted by the packets each report
covers:

    est = (est × n + window_loss × packets) / (n + packets),  n ≤ loss-smoothing

`n` is the packets averaged so far, so the estimate is the plain average
until that many have arrived, then a moving average whose memory is
counted in packets, not time: a report of 3 packets moves it by about
3/2000 of the difference. At 3 % loss over 2000 packets the estimate is
within about ±0.5 %. The controller acts on it once a quarter of
`loss-smoothing` packets have been seen. Both ends keep the same estimate
for their inbound direction (`_rx` 39–41). Lower `loss-smoothing` reacts
faster and is noisier.

The controller only runs when a report arrives, and reports only come while
traffic flows. An idle link therefore keeps its last FEC state until traffic
starts again.

**ARQ (ingress 100, on each NAK).** For each sequence in the NAK, at most
`depth`:
1. The tag must match.
2. While FEC is on, the packet must be within the last `arq-with-fec`
   packets (or ARQ is off, or it keeps going, depending on the setting).
3. If so, the stored packet is copied into the NAK's buffer, retyped RETX
   and cloned out.

## Receiver

**Sequence (ingress 120).**
- Extends the 16-bit sequence around the highest seen.
- A forward jump > 1 is a gap: counted as raw loss and NAKed right away.
- A packet older than the highest is reordered (DATA) or recovered (RETX).
- Duplicates are caught with a test-and-set bitmap covering 1024 sequences:
  one word per 64 sequences in the `_dup` array map (window sized as above),
  atomic `calc-map or`.
- A forward jump over 16,384, or a backward jump on a sequence flagged as
  restarted (by 64 or more, or below the sequence this receiver started at,
  `_rx` 58), resynchronises without counting loss (peer reboot). The second
  case is a peer reinstalled while its old instance's packets were still in
  flight: the receiver started on one of those, and the new instance's first
  packets looked late, which took them off the raw loss and hid the gaps
  among them (about 1 % less loss on a 3 % link). The report
  window across a resync is empty: it used to wrap to an enormous window
  with no loss, which replaced both loss estimates with ~0 for minutes
  (the sender also ignores a window of 2^32 packets or more from an older
  peer).

**Telemetry.**
- **Transit:** `arrival − ts` in 4 µs units. The clock offset between the
  hosts is unknown, so only differences are used.
- **Jitter:** RFC 3550, `J += (|D| − J) / 16`.
- **Queueing delay:** transit minus the smallest transit seen in this and the
  previous 30 s window. This is the one-way delay above the base delay of the
  path, without synchronised clocks. Clock drift (ppm) moves the base slowly,
  and the window absorbs it.
- **RTT:** measured at the sender from the echoed timestamp.

**FEC (ingress 130 and 110).** Members are XORed into receive slot
`block % 16` (shared buffer `_frx`, atomic XOR). The slot also keeps the
block id, the member count and the XOR of member sequence numbers. As on the
sender, TCP/UDP members are folded in with their true checksum. Virtual NICs
can deliver packets whose checksum field still holds the partial value.

When the parity arrives (110):

| Members received | Result |
|---|---|
| n | the slot is cleared |
| n − 1 | the missing packet is rebuilt (see below) |
| fewer | counted as a failed block |

To rebuild:
1. Put back the saved checksum bytes in the parity.
2. Missing packet = parity XOR slot. Its sequence number is the parity's
   `seq_xor` XOR the slot's.
3. Check the IPv4 header checksum and the TCP/UDP checksum.
4. Run the duplicate check.
5. Deliver.

A rebuild that fails a check is dropped and counted (`fec_bad`); it is never
delivered.

**Deliver (ingress 130).** Removes the shim with `strip-l2 8 0x0800`.
`bpf_skb_adjust_room` refuses non-IP packets, so this uses the VLAN helpers
and needs no payload copy or redirect; `skb->protocol` becomes IPv4.
Retransmissions get their TCP/UDP checksum recomputed, because they were
stored before the sender's NIC completed it.

When a NAK or report is due, a copy of the packet is delivered
(`clone ... ingress`). The original is turned into the control frame, with
MACs swapped, and redirected out of the interface.

**Packet pairs (ingress 100).** Probe 1 opens a pair: its arrival time is
kept and a byte count started. Every frame that arrives until probe 2 adds
its length + 24 bytes (preamble, inter-frame gap, FCS), because it crossed
the bottleneck between the two copies; this happens before any EtherType
match, so ARP and other traffic count too. Probe 2 closes the pair:

    sample = bytes (including probe 2) × 8 / (t2 − t1)

A sender queue that put other packets between the copies therefore does
not make the link look slower. The last 16 samples are kept (`_rx` 60–75)
and the estimate (`_rx` 19) is the fourth largest, about the 80th
percentile; with fewer samples the same share from the top (the largest of
up to 4, the 2nd of up to 8, the 3rd of up to 12; taking the 4th from the
start gave the smallest of 3 samples, 1.3 Mbit/s on a 10 Mbit/s link). The
probe program keeps the four largest (`_rx` 53–56) and the program that
sends reports picks among them, which keeps the choice out of the probe
program's verifier budget: delay jitter (each packet delayed independently, as netem
does) only stretches a gap and a receiver that batches packets only
shrinks one, so the estimate is right while at least 4 of 16 pairs got
through cleanly and no more than 3 were squeezed. A pair open for more than
1 s is abandoned. The old estimator (an average of single samples) settled
near half the rate on a link where half the pairs were stretched by jitter.

**Capacity window.** The 16 samples span 160 s at the default probe
interval, so after the capacity changes the estimate keeps the old value
for minutes (longer while FEC slows the probes). With `capacity-window`
set, each sample's time is kept too (`_rx` 76–91), and the probe program
clears every sample older than the window before counting the rest
(`_rx` 57); the report program then takes the same share from the top of
those. The `leo` profile probes every 5 s with a 15 s window, so the
estimate follows each satellite after two or three probes and never mixes
in the previous one. With no sample in the window the last estimate stays.
A window shorter than the probe interval is allowed (the generator warns):
then only the newest sample counts. Runtime: `bpfc-dataplane-status set
capacity-window 15s` (or `off`).

<a id="probe-trains"></a>**Probe trains.** On a link that delivers in frames
(Starlink releases traffic every 1.33 ms) the two copies of a pair usually
leave in the same frame and arrive together, which reads far too fast; split
across frames they read one packet per frame, whatever the rate. FRR's
packet-pair work (ospfd/nhrpd) measured 243 Mbit/s with pairs on an emulated
15 Mbit/s Starlink uplink, and 16.6 with trains and a median. The same holds
here (tests: pairs 590–760 % of the true rate, trains about 100 %).
With `probe-train` (ms) the sender clones the probe packet into a train in
one pass: head (probe 1), fillers, tail (the packet itself, probe 2), as
many as cross the link in that long at the rate the peer measured for this
direction (`_tx` 36; 16 until there is one), 3 to `probe-train-max` (≤ 256).
The receiver counts the bytes of every frame from the first filler at
`probe-train-skip` percent into the train (so the first frame and a
scheduler's grant ramp-up are left out) to the tail, and divides by the
time; fillers are dropped there, not counted as duplicates (`_rx` 96). A
train whose tail is lost gives no sample. `capacity-percentile` (50 in
`leo`) replaces the pair rule (the high share from the top, right for pairs
stretched by jitter, wrong for trains): the K-th largest sample in the ring
(or window), found bit by bit without branches in the report program. The
`leo` profile's 20 ms trains every 3 s cost about 0.7 % of the link; at most
256 packets per train. Runtime: `set eth0 probe-train 20ms|off`,
`probe-train-max`, `probe-train-skip`, `capacity-percentile 50|off`.
Not done yet: a schedule that keeps probes away from the 15 s boundaries
(needs a synchronised clock), and passive samples from the data itself.

**Reports.** Sent every `report-interval` while data arrives. Each report
covers the last window:
- raw loss = (gaps − late arrivals) / sequences expected
- residual loss = (raw − FEC − ARQ recoveries) / expected

## Maps and keys

### Map names

Map names are `<prefix>_<suffix>`, with suffixes `tx rx pcpu cfg arq atag
ftx frx fsl dup`. The default prefix is `dp` followed by 8 base32 characters
(`a-z2-7`, 40 bits) of the interface name's SHA-256, e.g. `dptqzkrr7f` for
`eth0`. Interface names may contain characters the kernel does not allow in
object names and can be 15 bytes long; a hashed prefix gives names of 15
characters at most, so the pinned name and the name the kernel shows
(`bpftool map show`) are the same and unique. The alphabet has no `-`, so a
name never looks like a command-line option.

- `bpfc-dataplane-gen -i <if> --map-prefix` prints the prefix;
  `bpfc-dataplane-status` shows it (`Maps`, and `maps=` with `-1`).
- `--prefix NAME` picks a readable one instead (1-10 of `A-Z a-z 0-9 _ .`).
- The generator refuses a prefix that another interface in the output
  directory already uses (a hash collision, about 1 in 200 million for 100
  interfaces, or the same `--prefix` twice).
- Interface names are checked as the kernel does: 1-15 bytes, not `.` or
  `..`, no `/`, `:`, `%` or whitespace. In the program header and in
  `-1` output they are percent-encoded (`iface=a%23b`).
- Renaming an interface gives it new maps. `--remove-maps -i <if> [-m DIR]`
  deletes an interface's pinned maps, including the `dp_<if>_*` names of
  generator version 2; remove its programs first.

All scalar maps are bpfc's 8-byte-key / 8-byte-value LRU hash maps. The
status script decodes them with `bpfc -r`.

`<prefix>_tx` — sender side, and what the peer reports:

| Key | | Key | |
|---|---|---|---|
| 1 | next sequence (= packets sent) | 21 | RTT µs (EWMA) |
| 2 | packets sent | 22 | FEC on since (ms) |
| 3 | IP bytes sent | 23 | parity sent early (block timeout / FEC off) |
| 4 | bypassed (too large) | 24 | FEC member packets |
| 5 | block counter | 30 | last report (ms, CLOCK_MONOTONIC) |
| 6 | FEC ratio K in use, 0 = off | 31 | peer: packets received |
| 7 | last report with loss ≥ threshold (ms) | 32 / 33 | peer: loss / residual loss, bp, last window |
| 8 | FEC on/off changes | 34 / 35 | peer: jitter / queueing delay, µs |
| 9 | parity packets sent | 36 | peer: capacity kbit/s |
| 10 / 11 | last probe (ms) / probes sent | 37 / 38 | peer: duplicates / reordered |
| 12 | NAKs received | 39 / 40 | peer: FEC rebuilt / ARQ recovered |
| 13 | retransmitted | 41 / 42 | peer: residual lost / gaps (totals) |
| 14 | NAKed but no longer held | 43 | reports received |
| 15 | not retransmitted because FEC is on | 44 | peer MAC |
| 16 / 17 / 18 | congested / utilisation % / send rate kbit/s | 45 | peer: expected packets, last window |
| 19 / 20 | rate sample time / bytes | 46 / 47 | loss / residual loss estimate, 1/100 bp |
| 49 | last time the residual estimate was ≥ 1 % (ms) | 48 | packets in the loss estimate |
| 50 | repair failing (counts as congestion) | 60 / 61 | udp: learned peer address / port |
| 62 | udp: our address (learned) | 64 | udp-inline: addresses of the last packet sent (src << 32 \| dst) |
| 65 | udp: not sent, no peer or local address yet | 66 | udp: peer address changes learned |
| 67 | udp: last frame sent to the peer (ms) | 68 | udp: keepalives sent |
| 69 | probe packets sent (all trains) | | |

`<prefix>_rx` — receiver side:

| Key | | Key | |
|---|---|---|---|
| 1 | highest sequence + 1 | 21 / 22 | timestamp to echo / when it arrived |
| 2 | data packets received | 23 | last report sent (ms) |
| 3 | duplicates on the link | 24–26 | window start: highest, raw lost, residual |
| 4 | reordered (late) | 27 / 28 | loss / residual loss, bp, last window |
| 5 | gaps (raw loss, total) | 29 | reports sent |
| 6 / 7 | FEC rebuilt / ARQ recovered | 30 | peer's FEC K for this direction |
| 8 | FEC blocks that could not be rebuilt | 31 | too old for the duplicate window |
| 9 | parity received | 32 | last data (ms) |
| 10 | NAKs sent | 33 | peer MAC |
| 11 | jitter × 16 (4 µs units) | 34 | rebuilds that failed checks |
| 12–15 | transit state, delay windows | 35 | expected packets, last window |
| 16 | queueing delay µs (EWMA) | 36 | resyncs |
| 17–20 | probe state, capacity kbit/s, probes | 37 / 38 | redundant FEC rebuilds / retransmissions |
| 39 / 40 | loss / residual loss estimate, 1/100 bp | 41 | packets in the loss estimate |
| 42 / 43 | bytes in the open pair / pairs measured | 52 | last capacity sample, kbit/s |
| 49 | last time the inbound residual estimate was ≥ 1 % (ms) | 53–56 | four largest capacity samples |
| 57 | capacity samples in use (in the window) | 58 | sequence this receiver started or resynced at |
| 60–75 | last 16 capacity samples, kbit/s | 76–91 | when each was taken (ms) |
| 92 | udp-inline: addresses of the last packet received | 93 / 94 | UDP carriers: frames received / refused |
| 95 | udp: keepalives received | 96 | train fillers received |
| 59 | train: timing restarted at the head-skip filler | | |

`<prefix>_cfg` holds runtime overrides; 0 or missing means the generated
value. Use `bpfc-dataplane-status set`, or `bpfc -w <prefix>_cfg <key> <value>`.

| Key | Setting | Key | Setting |
|---|---|---|---|
| 1 | FEC threshold, bp | 9 | ARQ depth while FEC is on |
| 2 | cool-down, ms | 10 | report interval, ms |
| 3 / 4 / 5 | K fixed / min / max | 11 | congestion: utilisation % |
| 6 / 7 | probe interval ms / backoff | 12 | FEC block timeout, ms |
| 8 | ARQ with FEC: 1 keep, 2 off, 3 last N | 13 | minimum probe size, bytes |
| 14 | FEC mode: 1 off, 2 on, 3 auto | 15 | congestion: queueing delay, ms |
| 16 | FEC floor: 1–15, or 16 for none | 17 | loss-smoothing, packets |
| 18 | capacity window, ms (≥ 1 day: off) | 19 / 20 | udp: peer address / port |
| 21 | udp: local address | 22 | udp: keepalive, ms (≥ 1 day: off) |
| 23 | probe train, ms (≥ 1 day: pairs) | 24 | probe train, most packets |
| 25 | probe train skip, percent + 1 | 26 | capacity percentile (> 100: the pair rule) |

Also: `<prefix>_pcpu` (FEC block per CPU), `<prefix>_arq` (ring × 1504
bytes), `<prefix>_ftx` (per-CPU 1504 bytes), `<prefix>_frx` (slots × 1504
bytes), and three array maps that never evict: `<prefix>_atag` (ring tags,
`seq << 16 | length`), `<prefix>_fsl` (FEC slot state at `slot × 4`: block + 1,
members, seq-xor) and `<prefix>_dup` (duplicate bitmap). `_tx`, `_rx`,
`_pcpu` and `_cfg` are bpfc's hash maps (10,000 entries). Regenerating with
other sizes replaces the pinned maps of the old sizes.

## bpfc changes

New general-purpose instructions:
- `calc-map` (atomic add/or/and/xor/xchg)
- `xor-packet[-keyed]` and `zero-buffer[-keyed]`
- sized `buffer-map` / `shared-buffer-map`
- `calc-csum`, `insert-l2`, `remove-l2`, `strip-l2`
- `get cpu`, `calc hton/ntoh`
- `array-map NAME entries` (64-bit values, keys 0..entries-1, never evicted;
  works with `get map`, `set map`, `calc-map`, `bpfc -r` and `-w`)
- declarations that state sizes replace a pinned map of other sizes
- buffer copies at a constant offset may fill the whole entry (a variable
  offset still caps offset and length at half the entry each)
- `bpfc -w`
- `verified=` in `bpfc -I`

Fixes found along the way:
- **`clone ... egress`** cloned to *ingress*: the local `BPF_F_EGRESS`
  define is 1, which is `BPF_F_INGRESS`.
- **`free`** removed the variable below the freed one.
- **Reusing a freed variable slot** zeroed the variable on top of the stack.
- **`set val` of an 8-byte constant** wrote two 32-bit halves, so the
  verifier lost the value (loop bounds).
- **Loading always used a level-2 verifier log**, which fails large valid
  programs with ENOSPC. bpfc now loads without a log and retries with one
  only on failure.
- **`recalc-tcp/udp-csum`** assumed a 20-byte header and could not sum more
  than 512 bytes.
- **`load-packet-keyed`** with a constant key read an uninitialised key.
- **Map names longer than 15 characters**, or with `-`, overflowed or broke
  map creation.

The existing tests give the same results before and after these changes.

## Limits

- IPv4 only, also as the UDP carriers' outer protocol. IPv6 passes through unprotected. Later, the same shim could ride
  in IPv4 (protocol 253): receiver offsets move by 20 bytes and decap becomes
  `bpf_skb_adjust_room` at the network layer.
- UDP carriers: one peer per interface (point-to-point); peer learning has
  no authentication, so a host that can send to the port from inside
  `peer-learn-from` can take the peer's place (narrow it to the peer's ISP
  ranges, or filter the port upstream). The keepalive needs some IPv4
  traffic on the interface to ride on.
- XOR parity repairs one loss per block. With K = 2500 / loss_bp, about 3 %
  of blocks have two losses at 3 % loss. ARQ covers those when the RTT is
  short compared with the ARQ window.
- ARQ NAKs once per gap, for at most 32 packets, with no retry. Longer
  bursts are left to FEC (32 packets is 13 ms at the geo rate). On long links
  many retransmissions arrive after FEC has already rebuilt the packet
  (counted as redundant repairs); NAKing only after a block fails to rebuild
  would save that traffic.
- Packets lost at the very end of a burst of traffic aren't counted until a
  later packet shows the gap, so a run that ends with losses undercounts them.
- Reordering produces spurious NAKs;
  their retransmissions are dropped as duplicates (counted).
- The receive-side FEC slots are shared. If several CPUs receive members of
  the same block at once, a slot reset can race, and the rebuild then fails
  its checksum and is dropped. Frames with EtherType 0x88B5 normally all land
  on one receive queue, because RSS cannot hash them.
- Packet-pair probes see line rate through token-bucket shapers that still
  have burst credit, so capacity is overestimated there. The queueing-delay
  signal still detects congestion.
- With the default probe interval (10 s) the 16 samples span minutes; use
  `probe-rate` 1–10 on links whose rate changes or where many pairs are
  disturbed (jitter, cross traffic). Traffic from other senders sharing the
  bottleneck between the copies is not seen and lowers a sample.
- Tested on kernel 6.18 with veth pairs, including an emulated 800 ms link
  (`tests/link-emulator.py`) and a content check on every delivered datagram
  (`tests/udp-verify.py`). RHEL 9 (5.14) has every helper used: BPF atomics
  are 5.12, bounded loops 5.3, VLAN and adjust_room helpers older. The
  verifier cost is about 8× below the limit here, but has not been measured
  on 5.14.
