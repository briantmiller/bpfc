#!/usr/bin/env python3
"""Test helper: bridge two interfaces with a fixed one-way delay.

    link-emulator.py <if-a> <if-b> <delay-ms> [--a2b SPEC] [--b2a SPEC]

Frames received on one interface are sent out of the other <delay-ms> later,
in order, in both directions (a long-delay link such as a GEO satellite hop,
for test-dataplane.sh). Frames we transmit ourselves are ignored. Runs until
killed. Python is used only by the tests; the dataplane itself is bpfc.

--a2b / --b2a shape one direction like "tc qdisc ... netem" would (for
kernels without sch_netem): SPEC is comma-separated key=value with
  rate=20m     bits per second (k, m, g), counting the frame without FCS
  delay=150    one-way delay in ms (replaces <delay-ms> for this direction)
  jitter=10    +/- ms, uniform, netem's way: with a rate, a packet never
               leaves before the one ahead of it, but it can be held longer
  loss=3       random loss in percent, before the rate (as netem does)
  limit=1000   queue limit in packets (netem's default), excess is dropped
  order=1      with jitter but no rate, keep packets in order (netem would
               reorder them); for a kernel shaper (tbf) after the emulator

A Starlink-like link (as FRR's satrelay test bed models it) adds:
  frame=1.33   deliver in frames: what is due within a frame (ms) leaves
               together at its end, back to back
  redraw=15    every 15 s (wall clock, from second `offset`) the rate is
  vary=40      drawn again, +/- vary percent of rate=
  offset=12    first boundary second (12: :12, :27, :42, :57 past the minute)
  burst=30:200 after each redraw, lose 30 % of packets for 200 ms
  ratelog=F    append "<unix time> <bit/s>" to file F at start and at each redraw

A veth hands over frames whose TCP/UDP checksum the kernel left for the NIC
to finish. A real link only ever carries finished frames, so those checksums
are completed here (IPv4 directly after Ethernet, or after the dataplane's
8-byte shim, EtherType 0x88B5).

Socket buffers are forced to 32 MB (SO_RCVBUFFORCE, root only) so that bursts
are not dropped because of net.core.rmem_max. Frames the emulator itself
loses (kernel socket drops, send failures) are counted, and the totals are
written to stderr every 2 s ("emulator drops: rx <if> N / <if> N, tx ...").
"""
import array
import collections
import heapq
import random
import socket
import struct
import sys
import threading
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
PACKET_AUXDATA = 8
SOL_PACKET = 263
TP_STATUS_CSUMNOTREADY = 8
PACKET_STATISTICS = 6
SO_SNDBUFFORCE = 32
SO_RCVBUFFORCE = 33
send_errors = collections.Counter()


def csum16(data):
    if len(data) % 2:
        data += b"\0"
    a = array.array("H", data)
    if sys.byteorder == "little":
        a.byteswap()
    s = sum(a)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def finish_checksum(frame):
    etype = struct.unpack_from("!H", frame, 12)[0]
    ip = 14 if etype == 0x0800 else 22 if etype == 0x88B5 else None
    if ip is None or len(frame) < ip + 20 or frame[ip] >> 4 != 4:
        return frame
    ihl = (frame[ip] & 15) * 4
    tot = struct.unpack_from("!H", frame, ip + 2)[0]
    proto = frame[ip + 9]
    if struct.unpack_from("!H", frame, ip + 6)[0] & 0x3FFF or proto not in (6, 17):
        return frame
    l4 = ip + ihl
    l4len = tot - ihl
    off = l4 + (16 if proto == 6 else 6)
    if l4len < 8 or len(frame) < l4 + l4len:
        return frame
    f = bytearray(frame)
    f[off:off + 2] = b"\0\0"
    pseudo = bytes(f[ip + 12:ip + 20]) + struct.pack("!BBH", 0, proto, l4len)
    c = 0xFFFF - csum16(pseudo + bytes(f[l4:l4 + l4len]))
    if proto == 17 and c == 0:
        c = 0xFFFF
    struct.pack_into("!H", f, off, c)
    return bytes(f)


def open_if(name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    for force, plain in ((SO_RCVBUFFORCE, socket.SO_RCVBUF), (SO_SNDBUFFORCE, socket.SO_SNDBUF)):
        try:
            s.setsockopt(socket.SOL_SOCKET, force, 32 << 20)
        except OSError:
            s.setsockopt(socket.SOL_SOCKET, plain, 32 << 20)
    s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    s.bind((name, 0))
    return s


def parse_spec(spec, delay):
    cfg = {"rate": 0.0, "delay": delay, "jitter": 0.0, "loss": 0.0, "limit": 1000, "order": 0,
           "frame": 0.0, "redraw": 0.0, "vary": 0.0, "offset": 12.0, "burst": (0.0, 0.0), "ratelog": None}
    for item in filter(None, (spec or "").split(",")):
        k, v = item.split("=", 1)
        if k == "rate":
            mult = {"k": 1e3, "m": 1e6, "g": 1e9}.get(v[-1].lower(), 1)
            cfg["rate"] = float(v.rstrip("kKmMgG")) * mult
        elif k in ("delay", "jitter"):
            cfg[k] = float(v) / 1000.0
        elif k == "loss":
            cfg["loss"] = float(v) / 100.0
        elif k in ("limit", "order"):
            cfg[k] = int(v)
        elif k == "frame":
            cfg["frame"] = float(v) / 1000.0
        elif k in ("redraw", "offset"):
            cfg[k] = float(v)
        elif k == "vary":
            cfg["vary"] = float(v) / 100.0
        elif k == "burst":
            pct, ms = v.split(":")
            cfg["burst"] = (float(pct) / 100.0, float(ms) / 1000.0)
        elif k == "ratelog":
            cfg["ratelog"] = v
        else:
            raise SystemExit("unknown key %r in %r" % (k, spec))
    cfg["base"] = cfg["rate"]
    cfg["epoch"] = None
    cfg["since"] = -1e9
    return cfg


def redraw(cfg):
    """Starlink-like: a new rate at each wall-clock boundary."""
    if not cfg["redraw"]:
        return
    epoch = int((time.time() - cfg["offset"]) // cfg["redraw"])
    if epoch == cfg["epoch"]:
        return
    first = cfg["epoch"] is None
    cfg["epoch"] = epoch
    cfg["rate"] = cfg["base"] * (1 + random.uniform(-cfg["vary"], cfg["vary"]))
    if not first:
        cfg["since"] = time.monotonic()
    if cfg["ratelog"]:
        with open(cfg["ratelog"], "a") as f:
            f.write("%.3f %d\n" % (time.time(), cfg["rate"]))


def forward(rx, tx, cfg):
    queue = []            # heap of (time to send, order, frame), like netem's tfifo
    cv = threading.Condition()
    order = [0]
    last = [0.0]          # time to send of the packet last queued

    sent = [-1.0]         # when the previous frame went out

    def sender():
        while True:
            with cv:
                while not queue:
                    cv.wait()
                due, _, frame = queue[0]
                if cfg["rate"] and not cfg["frame"]:
                    # A shaped link needs a frame's serialization time after
                    # the one before it. When this thread wakes late, two due
                    # frames would otherwise go out back to back, and the
                    # peer would see the link as much faster than it is
                    # (packet-pair probes on slower machines, e.g. aarch64).
                    due = max(due, sent[0] + len(frame) * 8 / cfg["rate"])
                wait = due - time.monotonic()
                # Shaped: sleep until 2 ms before, then spin (yielding the
                # GIL), so the gap is not stretched by a late wake-up either.
                early = 0.002 if cfg["rate"] and not cfg["frame"] else 0.0
                if wait > early:
                    cv.wait(wait - early)
                    continue
                if wait <= 0:
                    heapq.heappop(queue)
                    sent[0] = time.monotonic()
            if wait > 0:
                while time.monotonic() < due:
                    time.sleep(0)
                with cv:
                    # still the head: with a rate, every frame queued
                    # meanwhile is due after the last one queued
                    heapq.heappop(queue)
                    sent[0] = time.monotonic()
            for attempt in range(50):
                try:
                    tx.send(frame)
                    break
                except BlockingIOError:
                    time.sleep(0.0002)
                except OSError:
                    send_errors[tx.fileno()] += 1   # lost, counted
                    break

    threading.Thread(target=sender, daemon=True).start()
    while True:
        frame, anc, _, addr = rx.recvmsg(65535, socket.CMSG_SPACE(32))
        if addr[2] == PACKET_OUTGOING:
            continue
        for level, ctype, cdata in anc:
            if level == SOL_PACKET and ctype == PACKET_AUXDATA:
                if struct.unpack_from("I", cdata, 0)[0] & TP_STATUS_CSUMNOTREADY:
                    frame = finish_checksum(frame)
        if cfg["loss"] and random.random() < cfg["loss"]:
            continue
        redraw(cfg)
        now = time.monotonic()
        if cfg["burst"][0] and now - cfg["since"] < cfg["burst"][1] and random.random() < cfg["burst"][0]:
            continue
        delay = cfg["delay"]
        if cfg["jitter"]:
            delay += random.uniform(-cfg["jitter"], cfg["jitter"])
        with cv:
            if len(queue) >= cfg["limit"]:
                send_errors["limit"] += 1
                continue
            if cfg["rate"]:
                # netem: the last packet queued is the reference point
                if queue and last[0] > now:
                    delay = max(0.0, delay - (last[0] - now))
                    now = last[0]
                delay += len(frame) * 8 / cfg["rate"]
            due = now + max(0.0, delay)
            if cfg["order"] and queue and due < last[0]:
                due = last[0]
            last[0] = due
            if cfg["frame"]:
                # leaves with the frame it falls in, at that frame's end
                due = (int(due / cfg["frame"]) + 1) * cfg["frame"]
            order[0] += 1
            heapq.heappush(queue, (due, order[0], frame))
            cv.notify()


def rx_drops(s):
    # struct tpacket_stats { unsigned tp_packets, tp_drops; } - reset on read
    return struct.unpack("II", s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))[1]


def report(a, b, names):
    total = {names[0]: 0, names[1]: 0}
    while True:
        time.sleep(2)
        new = rx_drops(a), rx_drops(b)
        if new[0] or new[1]:
            total[names[0]] += new[0]
            total[names[1]] += new[1]
        print("emulator drops: rx %s %d / %s %d, tx %s %d / %s %d, queue limit %d" % (
            names[0], total[names[0]], names[1], total[names[1]],
            names[0], send_errors[a.fileno()], names[1], send_errors[b.fileno()],
            send_errors["limit"]),
            file=sys.stderr, flush=True)


def main():
    # Hand the GIL over sooner than the default 5 ms, so a thread due to
    # send is not kept waiting by one busy receiving or checksumming.
    sys.setswitchinterval(0.0005)
    args = sys.argv[1:]
    specs = {"--a2b": None, "--b2a": None}
    while len(args) > 3 and args[-2] in specs:
        specs[args[-2]] = args[-1]
        args = args[:-2]
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    a, b = open_if(args[0]), open_if(args[1])
    delay = float(args[2]) / 1000.0
    a2b, b2a = parse_spec(specs["--a2b"], delay), parse_spec(specs["--b2a"], delay)
    threading.Thread(target=report, args=(a, b, args[0:2]), daemon=True).start()
    threading.Thread(target=forward, args=(a, b, a2b), daemon=True).start()
    forward(b, a, b2a)


if __name__ == "__main__":
    main()
