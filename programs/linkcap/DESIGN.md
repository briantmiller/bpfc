# linkcap: per-neighbor loss and capacity from packet accounting

`bpfc-linkcap-gen` generates two bpfc programs per interface (TC ingress and
egress). They count every unicast IP packet per neighbor, exchange the counts
with the neighbor in small report and reply frames, and turn each exchange
into one sample: loss, delivered rate, queueing delay and RTT.
`bpfc-linkcap-status` makes a capacity estimate from the samples; a shaper
polls it (`-1` or `-j`). Both ends of a measured link must run it.

The method is the one of ITU-T Y.1731 loss measurement (LMM/LMR): the
counters are cumulative and never reset, and loss is the difference between
two consecutive exchanges. A lost report or reply costs one sample, nothing
more; packets counted on another CPU while a report is being made, or a
report overtaking data in a multi-queue qdisc, move a few packets from one
interval to the next.

```bash
bpfc-linkcap-gen -i eth0                       # /etc/bpfc/interfaces.d/eth0/{ingress/5,egress/60000}.bpfc
bpfc-linkcap-gen -i gre1 -i wg0 --profile leo
bpfc-linkcap-gen -i eth0 --setup-hints         # offloads, the report class
systemctl reload bpfcd
bpfc-linkcap-status                            # one row per neighbor
bpfc-linkcap-status detail eth0
bpfc-linkcap-status -1                         # key=value per neighbor, for a shaper
bpfc-linkcap-status set eth0 delay-threshold 20ms
```

## Neighbors and link types

| Link (`--link`, detected from `ip -d link`) | Neighbor key | Reports carried as |
|---|---|---|
| `eth`: Ethernet (veth, NICs, VLAN devices, bonds) | the MAC: destination at egress, source at ingress (frames to `$IFMAC` only) | EtherType 0x88B6 (IEEE local experimental; the dataplane uses 0x88B5) |
| `p2p`: no link-layer header (point-to-point GRE, IPIP, PPP, WireGuard, tun) | the link itself: one neighbor, `peer` | IPv4, protocol 253 (RFC 3692 experimental), 0.0.0.0 to 0.0.0.0 |
| `mgre`: multipoint GRE (`remote any`, NHRP/DMVPN) | the outer IPv4 address: destination at egress, source at ingress | inner IPv4, protocol 253, behind the outer header |

- Measure a VLAN on its VLAN device (`eth0.100`), not on the parent: the key
  has no VLAN ID.
- Multicast and broadcast frames are not counted (receivers filter groups they
  have not joined, which would look like loss).
- A neighbor without linkcap drops the frames: an unknown EtherType, or a
  packet from the martian source 0.0.0.0.
- Up to `--neighbors` (64) neighbors per interface. Slots are not reused: a
  neighbor that goes away keeps its slot until the maps are removed
  (`--remove-maps`). Neighbors beyond the limit are counted as refused.

## What is counted

The IP length (IPv4 total length, IPv6 payload length + 40) of every unicast
IPv4/IPv6 packet, on every link type, so padding to 60 bytes, a stripped
VLAN tag or a tunnel header make no difference between the ends. A GSO or GRO
packet counts as the segments it is made of (`gso_segs`), with its own IP
length as its bytes: the headers of the later segments are missing, so turn
TSO/GSO/GRO off on measured interfaces (`--setup-hints`). The status script
adds a per-packet overhead (`overhead`, default by link type: Ethernet 14,
GRE/IPIP 24, mGRE 20 + GRE header, WireGuard 60, PPP 2) for the wire rate.

Hooks: the egress program is the **last** egress program (priority 60000):
what a later program or the qdisc drops is counted as sent and shows as loss.
The ingress program is the **first** (priority 5), before anything that drops.

## Reports and replies

BPF cannot create a packet, and BPF timers cannot send one. A report is
therefore a clone of a real packet:

1. Before an egress packet is counted, the program looks at the next neighbor
   in turn (round robin over the slots). If its interval has passed, something
   was sent to it since its last report, and the packet is not GSO, one CPU
   wins the slot with an atomic exchange of its last-report time.
2. The packet is marked (Ethernet: destination = the neighbor, source
   `4c:43:00:00` + slot, EtherType 0x88B6; raw IP: IP ID 0x4C43 and protocol
   253; mGRE: the same in the inner header, with the slot as inner source),
   cloned to the interface's egress, and restored.
3. The clone goes through the egress hook again, before the packet it was made
   from. There it becomes the report: 192 bytes, zero up to offset 128, the
   payload at 128, the counters read at that moment, and `skb->priority` set
   to `--report-priority`.

The neighbor's ingress program answers with the counts it has received by
then, rewriting the report into the reply in place and sending it back out of
the same interface (a hairpin clone); the original is dropped.

Nothing is sent to an idle neighbor. Its capacity is not needed, and the next
report covers the whole gap (the counters are cumulative).

### Why 128 zero bytes

A clone of a locally sent TCP/UDP packet can still be waiting for its
checksum (CHECKSUM_PARTIAL): the NIC or the kernel writes it at the
transport header + 16 (TCP) or + 6 (UDP) of the original packet, at most
about 92 bytes in. That area is part of the report and zero; the payload
starts after it. Zeroing it also means nothing of the cloned packet leaves
with the report (trimming and growing an skb brings the old bytes back).

### Payload (at offset 128; on mGRE at 128 from the inner header)

Eight 8-byte words, network order:

| Word | Report | Reply |
|---|---|---|
| 0 | 0x4C43, version 1, type 1, sequence (32 bits) | the same, type 2 |
| 1 | the neighbor's key | the reporter's key |
| 2, 3 | packets and IP bytes sent to the neighbor (cumulative) | echoed |
| 4 | send time (sender's CLOCK_MONOTONIC, ns) | echoed |
| 5, 6 | 0 | packets and IP bytes received from the reporter (cumulative) |
| 7 | 0 | receive time (receiver's clock, ns) |

### Multipoint GRE

On an mGRE device (`ipgre_header_ops`) TC sees outer IPv4 + GRE + the inner
packet at both hooks; the generator compiles the inner offset (20 + the GRE
header, 4 + 4 for each of key, checksum and sequence, from the tunnel's
o-flags) as a constant. A clone redirected out of such a device loses the
outer header (the kernel pulls everything before the network header), so
reports and replies come back through egress as bare inner IPv4 packets with
protocol 253. The program then adds the outer header room
(`add-head-bytes`) and writes the destination (the neighbor's NBMA address);
ip_gre takes the destination from there and builds the outer header and the
GRE header itself, with TTL 0 = the inner TTL. **Not run yet**: the test
kernel has no ip_gre, so this path is compile-tested only.

Reports are made from IPv4 packets only on raw-IP and mGRE links
(`skb->protocol` stays the one of the packet the clone came from, and ip_gre
puts it in the GRE header). An IPv6-only point-to-point link gets no reports.

## Samples

When a reply arrives, the reporter compares it with the previous reply from
that neighbor:

- sent = Δtx packets, received = Δrx packets (and the same for bytes); loss
  = sent − received
- interval = Δ receive time (the receiver's clock only)
- delivered rate = Δrx bytes / interval
- one-way delay = receive time − send time (two clocks: only its changes
  mean anything); queueing delay = one-way delay − the lowest in
  `baseline-window`, kept as two half-window minimums
- RTT = now − send time (the reporter's clock only)

Each sample goes into a 64-entry ring per neighbor. A reply older than the
last one is ignored; counters that went backwards (the neighbor's maps were
recreated) restart the comparison. Samples are always taken by the end that
sends: each end measures its own egress direction, which is the direction its
shaper controls.

## Capacity

`bpfc-linkcap-status` reads the samples within `capacity-window`:

- A sample whose queueing delay is above `delay-threshold` is **at capacity**:
  the bottleneck has a standing queue and delivers at its rate. Capacity is
  the median delivered rate of those samples (at least 3).
- Otherwise the path had room, and the highest delivered rate of those
  samples is a **lower bound**.
- Loss without a rise in delay is link loss (radio, SATCOM, pLEO), not
  congestion, and does not make a sample at capacity.
- The state is the latest sample's: `under` or `at`; `idle` without samples,
  `no-reply` when reports go out and nothing comes back.

The local shaper can hide the link: when it is the bottleneck, it is what is
measured. Reports and replies carry `--report-priority` (default 7,
TC_PRIO_CONTROL, band 0 of prio/pfifo_fast; an HTB class id such as 0x10010
for 1:10) so they can bypass it, and the queueing delay is the link's. A
shaper driven by this should probe upwards while the state is `under` and
the link is loaded, and back off when it turns `at` (as cake-autorate does).

## Maps

Suffix `lc` + 8 base32 characters of SHA-256(interface) (`--prefix` to
choose), so `NB_lcabcdefgh` is the kernel name too.

| Map | Kind | Contents |
|---|---|---|
| NB | hash, 4 × neighbors | key → slot + 1 |
| NK | array, neighbors | slot → key |
| TX, RX | array, 2 × neighbors | slot × 2: packets, + 1: IP bytes (cumulative) |
| ST | array, 16 × neighbors | per slot: last report time, report sequence, packets at the last report, last reply sequence, the last reply (5 words), the two delay minimums and the half-window start, last reply time, samples taken, last report answered |
| RG | array, 512 × neighbors | per slot, 64 samples of 8 words: time (ms), interval (µs), sent and received packets, sent and received bytes, queueing delay (µs), RTT (µs) |
| CF | array, 64 | 0–4 runtime settings (0 = generated value; overhead + 1); 8 slots handed out, 9 round robin, 10–17 counters (refused, GSO skipped, reports sent, replies sent, replies received, reports received, stale replies, counter resets) |

Runtime settings (`bpfc-linkcap-status set IF ...`): `interval` (CF 0, used
by the programs), `baseline-window` (CF 2, programs), `delay-threshold`
(CF 1), `capacity-window` (CF 3) and `overhead` (CF 4), used by the status
script.

## Profiles

`default` (250 ms reports, 60 s baseline, 10 ms threshold, 15 s window),
`leo` (200 ms, 15 s baseline: a Starlink path changes every 15 s, 20 ms
threshold), `geo` (500 ms, 120 s baseline, 30 ms threshold, 30 s window).
Local ones go in `/etc/bpfc/linkcap/profiles.d` (`--save-profile`).

## Cost and kernels

No loops: each program is straight-line code (about 900–1500 instructions,
1,000–1,600 verified on 6.18), so it loads on RHEL 9 (5.14) as well as RHEL
10. Per packet: one hash lookup and two atomic adds, plus a few map reads for
the round robin. Per report: one clone each way; 192 bytes per neighbor per
interval (6 kbit/s at 250 ms).

## Not done

- mGRE has not run on a real kernel (see above). Outer IPv6 for mGRE.
- Reports from IPv6 packets on raw-IP links.
- Slot reuse for neighbors that went away.
- FRR export of the capacity (planned).
