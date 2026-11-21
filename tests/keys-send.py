#!/usr/bin/env python3
"""Sends hand-built Ethernet frames for tests/test-keys.sh (no scapy needed).

    keys-send.py <iface> <dst-mac> <spec> [<spec> ...]

A spec is key=value words separated by commas:
    l3=4|6|arp  proto=udp|tcp|icmp|<n>  src=<addr> dst=<addr>  sport= dport=
    ident=<n> (IPv4 identification; IPv6: flow label)  tos=<n>  ttl=<n>
    vlan=<id>  frag=mf|off  ihl=<5-15>  hbh=1 (IPv6 hop-by-hop header first)
    frag6=first|later|last (IPv6 fragment header)
    icmptype=<n> icmpid=<n>  tcpflags=<n> (default 24: PSH ACK; 2: SYN)
    len=<payload bytes>  count=<n>  gap=<seconds>
"""
import socket
import struct
import sys
import time


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def build(spec, smac, dmac):
    p = {}
    for w in spec.split(","):
        if w:
            k, v = w.split("=", 1)
            p[k] = v
    l3 = p.get("l3", "4")
    proto = p.get("proto", "udp")
    pnum = {"udp": 17, "tcp": 6, "icmp": 1 if l3 == "4" else 58}.get(proto)
    if pnum is None:
        pnum = int(proto)
    payload = b"k" * int(p.get("len", "16"))
    sport, dport = int(p.get("sport", "1000")), int(p.get("dport", "2000"))
    if pnum == 17:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    elif pnum == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, int(p.get("tcpflags", "24")), 8192, 0, 0) + payload
    elif pnum in (1, 58):
        l4 = struct.pack("!BBHHH", int(p.get("icmptype", "8" if l3 == "4" else "128")), 0, 0,
                         int(p.get("icmpid", "77")), 1) + payload
    else:
        l4 = payload
    if l3 == "arp":
        eth_type = 0x0806
        l3b = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + smac + socket.inet_aton(p.get("src", "10.88.0.1")) + \
            b"\0" * 6 + socket.inet_aton(p.get("dst", "10.88.0.2"))
    elif l3 == "4":
        eth_type = 0x0800
        src, dst = socket.inet_aton(p.get("src", "10.88.0.1")), socket.inet_aton(p.get("dst", "10.88.0.2"))
        if pnum in (6, 17):
            ph = src + dst + struct.pack("!BBH", 0, pnum, len(l4))
            c = csum(ph + l4)
            if pnum == 17:
                c = c or 0xFFFF
                l4 = l4[:6] + struct.pack("!H", c) + l4[8:]
            else:
                l4 = l4[:16] + struct.pack("!H", c) + l4[18:]
        elif pnum == 1:
            l4 = l4[:2] + struct.pack("!H", csum(l4)) + l4[4:]
        ihl = int(p.get("ihl", "5"))
        opts = b"\x01" * (4 * (ihl - 5))
        frag = {"mf": 0x2000, "off": 0x0010}.get(p.get("frag", ""), 0)
        hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, int(p.get("tos", "0")), 4 * ihl + len(l4),
                          int(p.get("ident", "1")), frag, int(p.get("ttl", "64")), pnum, 0, src, dst) + opts
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        l3b = hdr + l4
    else:
        eth_type = 0x86DD
        src = socket.inet_pton(socket.AF_INET6, p.get("src", "fd88::1"))
        dst = socket.inet_pton(socket.AF_INET6, p.get("dst", "fd88::2"))
        if pnum in (6, 17, 58):
            ph = src + dst + struct.pack("!IxxxB", len(l4), pnum)
            c = csum(ph + l4)
            off = {17: 6, 6: 16, 58: 2}[pnum]
            l4 = l4[:off] + struct.pack("!H", c or 0xFFFF) + l4[off + 2:]
        nh, ext = pnum, b""
        if p.get("frag6"):
            off = {"first": 0x0001, "later": 0x0008 << 3 | 0x0001, "last": 0x0008 << 3}[p["frag6"]]
            ext = struct.pack("!BBHI", nh, 0, off, 0x1234)
            nh = 44
        if p.get("hbh"):
            ext = struct.pack("!BB6s", nh, 0, b"\x01\x04\0\0\0\0") + ext
            nh = 0
        flow = int(p.get("ident", "1")) & 0xFFFFF
        l3b = struct.pack("!IHBB16s16s", 6 << 28 | int(p.get("tos", "0")) << 20 | flow,
                          len(ext) + len(l4), nh, int(p.get("ttl", "64")), src, dst) + ext + l4
    eth = dmac + smac
    if "vlan" in p:
        eth += struct.pack("!HH", 0x8100, int(p["vlan"]))
    eth += struct.pack("!H", eth_type)
    frame = eth + l3b
    if len(frame) < 60:
        frame += b"\0" * (60 - len(frame))
    return frame, int(p.get("count", "1")), float(p.get("gap", "0"))


def main():
    iface, dmac = sys.argv[1], mac(sys.argv[2])
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    smac = s.getsockname()[4][:6]
    for spec in sys.argv[3:]:
        frame, count, gap = build(spec, smac, dmac)
        for _ in range(count):
            s.send(frame)
            if gap:
                time.sleep(gap)


if __name__ == "__main__":
    main()
