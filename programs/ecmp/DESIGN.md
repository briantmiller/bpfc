# bpfc-ecmp: bandwidth-aware, policy-based ECMP

A pure routing layer. It runs on one router, needs nothing from its neighbours,
and is independent of the FEC/INT/ARQ dataplane: none of its code or maps are
shared. Packets change only as in any router: TTL, IP checksum, and MACs.

The kernel's routing table (fed by a routing daemon, static routes or anything
else) stays the only authority on what is a valid next hop.

## Programs

`bpfc-ecmp-gen` writes, per the `interfaces.d` layout:

| Where | Role |
|---|---|
| `<ingress>/ingress/<prio>` | the **selector**: picks the member for each flow, forwards |
| `<member>/egress/<prio>` | **accounting**: bytes, rate, utilisation, how much traffic should move |
| `<member>/ingress/<prio>` | counts what arrives (shown, not acted on) |

Members are Ethernet interfaces or tunnels. Ingress interfaces must be Ethernet
(`fib-lookup` needs the header); traffic arriving on a tunnel is routed by the
kernel as usual and still counted at the members it leaves by.

## How a next hop is known to be valid

`bpf_fib_lookup` picks among the next hops of a multipath route by hashing the
addresses, protocol and ports it is given (`fib_multipath_hash_policy=1`).
`fib-lookup ports %VAR` supplies chosen ports and protocol: the value alone
selects the next hop. That gives everything needed, with no copy of the routes
and no dependence on how the kernel hashes:

- **Finding the members.** Up to `sweep` values are tried; every member the
  route returns is noted with a value that selects it. Interfaces reached only
  by a less specific route are never returned, because the lookup sees only
  the most specific route.
- **Pinning.** A flow stores its value and interface.
- **Checking.** Every packet is looked up with the flow's value. The answer can
  only be the flow's interface while that interface is still a member of the
  route, so a withdrawn next hop is noticed on the next packet, with no timer.
  A lookup naming the interface directly (`output iface`) would not do: it
  succeeds through a less specific route.
- **After a route change** the value may select a different member even though
  the flow's own is still there. The sweep finds a new value for the same
  member, and the flow stays.

A lookup miss on the neighbour (result 7) is ordinary on tunnels, which have
no neighbour entries: a member is marked a tunnel by its accounting program.
On Ethernet it goes to the kernel for that packet.

`ip rule` matches on ports or protocol see the synthetic values; matches on
addresses, TOS and interface work.

## Flows

Mode sets the key: `l3`, `l3+proto`, `l3+tos`, `l4`, `l4+tos`, each with an
optional `-sym` so both directions share it. DSCP only (never ECN). Fragments
have no ports in `l4` modes, so all fragments of a datagram stay together.

The table is an array map of `flows` entries of 12 words, in two positions per
flow, so it never evicts by itself. A new flow takes a free or idle position.
With neither, it is not recorded and simply uses its hash: table pressure costs
balance, not packets.

Flow rate is measured per flow every `flow-interval` and smoothed (1/4).

## Member load

The egress program of each member adds up bytes (atomically), and the first
packet of each `rate-interval` window, on any CPU, works out the rate. That
claim is an atomic exchange, so exactly one CPU does it. The smoothed rate over
the effective capacity gives utilisation, in tenths of a percent. A member not
measured for 8 windows counts as idle.

Bandwidth is static at generation, and `bpfc-ecmp-status bw IF RATE` (or a
write of word 0 in the member map) replaces it at once, so an outside estimator
can drive it.

## Decisions

| When | What |
|---|---|
| new flow, below `shed` | the hash's member, one lookup, no sweep |
| new flow, its member at `shed` or more | **shed**: another member with room |
| `place balanced` | always compare two random members with room, take the one with more free capacity (power of two choices: comparing all of them makes every CPU pick the same one) |
| a policy matches | the first listed member that is valid and below `shed`; if all are above, the least loaded of them |
| member at `move` or more | flows move, until below `clear` |
| route changed | re-placed, on that packet |
| preferred member back | policy flows return at their next pause |

Moving is careful about several things:

- Only flows of at least `elephant` bit/s, so a move matters.
- Only during a pause of at least `gap`, so the flow cannot be reordered. Above
  `force` the wait is dropped: a link that full is dropping packets anyway.
- Never more than the excess: every `move-interval` the member works out how
  much must leave to reach `clear`, and each move spends from that.
- Only to a member with room for this flow below `clear`.
- The moved load is promised to the target immediately, so moves in the same
  window see it. The promise ends when the target's next measurement covers it.
- At most once per `dwell` per flow.

`--no-move IF` and a policy's `no-move` exclude flows from moves, for interfaces
where a path change would break them (a different NAT per interface). Route
changes still move them: the path is gone.

## Maps

`<prefix>_ft` flows, `_m` members (24 words each), `_if` ifindex -> member,
`_cfg` run-time settings (value + 1, 0 = generated), `_ctr` counters, `_ev` the
log of the last 256 decisions, `_sc` per-CPU scratch.

A member's interface number is learned from its own traffic, so a recreated
tunnel works once it sends. `bpfc-ecmp-status sync` does the same at once.

## Verifier

Instruction count is not the limit: 3 members is about 8,000 instructions. The
limit is the 1,000,000 the verifier may process. Verified (kernel 6.18):

| Members / policies | Verified |
|---|---|
| 3 / 0 | 58k |
| 3 / 3 | 93k |
| 8 / 8 | 230k |
| 16 / 0 | 134k |
| 16 / 16 | 541k |

Most of it is finding the members (the sweep, about 157 instructions per try),
recording the decision, and judging the members. The per-packet path is under
2%. The generator warns near the limit.

The design keeps the cost linear: the sweep only records (no judging), members
are then judged once each, and the loop bodies branch on data rather than on
what the sweep is for. Before the sweep, an always-zero map word is added to the
variables that hold constants on some paths, so those paths merge. It has to be
an addition: an OR keeps the known bits, which left the paths split and cost
about 4 times as much.

## Limits

- IPv4 only; other traffic is left to the kernel.
- Ingress interfaces must be Ethernet.
- Accounting is per interface, as configured. Tunnels sharing an underlay are
  separate members; their shared bottleneck is not seen.
- Up to 16 members, and 31 policies (fewer with many members: see the warning).
- `sweep` is capped at 64 tries. With 16 members, about 2% of searches miss a
  given member; the flow goes to another valid one. Flows placed by hash do not
  search.
- The flow table is not locked: two CPUs creating different flows in the same
  position at once can lose one (it continues on its hash). Likewise the first
  packets of one flow arriving on two CPUs can each create it, which only
  counts it twice. RSS keeps one flow on one CPU, so a flow's own counters are
  consistent.
