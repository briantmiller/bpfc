# dedup: IPv4 duplicate-packet removal for bpfc

TC programs that drop the second copy of an IPv4 packet, and `bpfc-dedup`, which shows what they did. Two flavours share one core (`dedup-lib.bpfc`):

| Include | Attach at | Table (scope) | Use |
|---|---|---|---|
| `dedup-iface.bpfc` | ingress or egress of any interface (also XDP) | one per interface and hook: `I_<if>`, `E_<if>`, `X_<if>` | duplicates within one interface's traffic |
| `dedup-global.bpfc` | ingress of the interfaces involved (TC or XDP; egress is refused) | one shared table: `G`, or `-s DD_GROUP=<name>` | the same stream arriving on several interfaces (1+1 redundant paths) |

Both define a macro, `dedup`, that you call inside your own matches, so only the traffic that can be duplicated is checked:

```
include dedup-iface.bpfc;
match udp; match udp-dst 5000-5010; dedup; end-match; end-match;
```

```bash
bpfc -i eth0 -d ingress -p 40 -f my-dedup.bpfc        # or bpfcd: interfaces.d/eth0/ingress/40.bpfc
bpfc-dedup                                            # every scope found in the map directory
bpfc-dedup -H 5 I_eth0                                # one scope, the last 5 duplicates
bpfc-dedup -j                                         # JSON
bpfc-dedup -z I_eth0                                  # zero its counters and history
```

The include files are installed in `/etc/bpfc/include`, bpfc's include path. `examples/` has a per-interface pair (ingress and egress of eth0) and a global 1+1 pair (wan1 and wan2).

## What counts as a duplicate

Same source, destination, IP protocol and IP identification, and the same signature: the IP total length plus one 16-bit L4 word (the TCP or UDP checksum, for other protocols the word at L4 offset 2, which is the ICMP checksum). Two different TCP/UDP packets with the same ID almost never match, even from stacks that reuse IDs on DF packets (RFC 6864).

Passed untouched, and counted:

- **Fragments** (MF or a fragment offset): every fragment shares its datagram's ID.
- **Non-TCP/UDP packets with DF set and ID 0**: atomic datagrams whose ID means nothing. Linux sends ID 0 on unconnected DF sockets. Non-TCP/UDP packets with DF clear, or with a non-zero ID, are checked.
- **Anything not IPv4.** IPv6 is a later step.

## When an earlier packet stops counting

Any one of these ends its window. Each limit is a constant, set with `-s NAME=value`:

| Constant | Default | Meaning |
|---|---|---|
| `DD_MS` | 1000 | time: the earlier packet is older than this many milliseconds |
| `DD_IDS` | 32768 | rollover: the sender's IP ID, per (source, destination, protocol), has advanced this far since, so the 16-bit ID may have wrapped. Only forward steps of under 32768 count, so late copies and reordering don't advance it. 0 turns it off. |
| `DD_PKTS` | 32768 | packets: this many packets of that (source, destination, protocol) have passed since. 0 turns it off. |

The window must be longer than the largest delay between copies (for 1+1 paths, the difference between the two paths) and shorter than the time the sender takes to wrap its ID. The rollover test covers a fast sender inside the time window.

Other constants: `DD_ENTRIES` (65536 packets remembered), `DD_FLOWS` (4096 source/destination/protocol triples tracked for the rollover and packet tests), `DD_HIST` (16 duplicates kept in the history), `DD_MODE` (`drop`, or `count` to only count). The maps are LRU hashes, so a full table forgets the oldest packets: a duplicate may then pass, but nothing legitimate is dropped. Programs that share a table (`dedup-global` on several interfaces) must use the same settings, since a map declared with another size is replaced.

## Maps (per scope S)

| Map | Kind | Contents |
|---|---|---|
| `DDS_S` | LRU hash, `DD_ENTRIES` | key `src<<32 \| id<<16 \| proto<<8 \| fold8(dst)`, value `signature<<32 \| 1<<31 \| tick` (tick = ktime>>20, about 1.05 ms, 31 bits) |
| `DDQ_S` | LRU hash, `DD_ENTRIES` | same key; the flow's ID advance and packet count when recorded |
| `DDF_S` | LRU hash, `DD_FLOWS` | per (source, destination, protocol): ID advance<<32 \| packets |
| `DDL_S` | LRU hash, `DD_FLOWS` | per (source, destination, protocol): 1<<16 \| last ID |
| `DDC_S` | array, 16 | counters 0-10 (checked, duplicates, new, expired by time / rollover / packets, fragments, atomic ID 0, replaced, history total, last duplicate time), settings 11-15 |
| `DDH_S` | array, 3 × `DD_HIST` | ring of duplicates: `src<<32 \| dst`, ktime ns, `proto<<48 \| id<<32 \| ifindex` |

Six maps per scope, so a program can use two scopes and still have room under bpfc's 16-map limit.

## Cost and limits

- Each `dedup` call is a full copy of the check: about 1,000 instructions, 1,200 verified (kernel 6.18). With many classes of traffic, set a flag in the matches and call `dedup` once (see `examples/interfaces.d/eth0/egress/40.bpfc`).
- The duplicate test is atomic (`calc-map xchg`), so two copies handled by two CPUs at the same moment can't both pass. The flow counters behind the rollover and packet tests use get/set and aren't atomic across CPUs. A lost update shifts those tests by a packet.
- GRO at ingress merges segments differently for each copy, so merged copies don't match. Turn GRO off on interfaces where TCP duplicates must be caught (`ethtool -K <if> gro off`). At egress, locally sent TCP/UDP still has its checksum pending, so the signature only covers the pseudo-header: the ID still separates packets, but less firmly.
- Kernel: RHEL 9 and 10 (the atomic exchange needs 5.12; no loops are used).
