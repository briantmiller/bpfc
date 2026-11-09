#!/usr/bin/env python3
"""Traffic for test-ecmp.sh.

  ecmp-send.py flows N [--count C] [--dst A] [--src A] [--tos T] [--sport P] [--dport P] [--size B]
      C datagrams on each of N UDP flows (source ports P, P+1, ...).
  ecmp-send.py rate BITS SECONDS [--flows N] [--dst A] [--src A] [--sport P] [--size B] [--tos T]
      A paced stream.
  ecmp-send.py raw SRC DST [--count C]
      IPv4/UDP built by hand, any source address (from a raw socket).
"""
import argparse, socket, struct, sys, time

def flows(a):
    ss = []
    for i in range(a.n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, a.tos)
        s.bind((a.src, a.sport + i))
        ss.append(s)
    for c in range(a.count):
        for s in ss:
            s.sendto(b"x" * a.size, (a.dst, a.dport))
        if a.gap: time.sleep(a.gap)

def rate(a):
    ss = []
    for i in range(a.flows):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, a.tos)
        s.bind((a.src, a.sport + i))
        ss.append(s)
    pps = max(a.bits / (8.0 * (a.size + 42)), 1)
    interval = 1.0 / pps
    end = time.monotonic() + a.seconds
    nxt = time.monotonic()
    i = 0
    payload = b"y" * a.size
    while True:
        now = time.monotonic()
        if now >= end: break
        if now < nxt:
            time.sleep(min(nxt - now, 0.005))
            continue
        ss[i % len(ss)].sendto(payload, (a.dst, a.dport))
        i += 1
        nxt += interval

def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return ~t & 0xffff

def raw(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    payload = b"z" * 64
    udp = struct.pack("!HHHH", a.sport, a.dport, 8 + len(payload), 0) + payload
    src = socket.inet_aton(a.src); dst = socket.inet_aton(a.dst)
    h = struct.pack("!BBHHHBBH4s4s", 0x45, a.tos, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    for _ in range(a.count):
        s.sendto(h + udp, (a.dst, 0))

p = argparse.ArgumentParser()
sub = p.add_subparsers(dest="cmd", required=True)
def common(q):
    q.add_argument("--dst", default="10.9.9.9"); q.add_argument("--src", default="192.168.1.2")
    q.add_argument("--tos", type=int, default=0); q.add_argument("--sport", type=int, default=2000)
    q.add_argument("--dport", type=int, default=5000); q.add_argument("--size", type=int, default=200)
q = sub.add_parser("flows"); q.add_argument("n", type=int); q.add_argument("--count", type=int, default=5); q.add_argument("--gap", type=float, default=0.0); common(q)
q = sub.add_parser("rate"); q.add_argument("bits", type=float); q.add_argument("seconds", type=float); q.add_argument("--flows", type=int, default=1); common(q)
q = sub.add_parser("raw"); q.add_argument("src_addr"); q.add_argument("dst_addr"); q.add_argument("--count", type=int, default=3); common(q)
a = p.parse_args()
if a.cmd == "raw": a.src, a.dst = a.src_addr, a.dst_addr
{"flows": flows, "rate": rate, "raw": raw}[a.cmd](a)
