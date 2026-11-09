#!/usr/bin/env python3
"""Records what arrives on interfaces, for test-ecmp.sh.

  ecmp-capture.py [-t SECS] [--raw] IF...   prints one line per IPv4 packet:
      <iface> <srcmac> <dstmac> <src> <dst> <proto> <sport> <dport> <ttl> <tos> <len> <csum-ok> <hexpayload-prefix>
"""
import argparse, select, socket, struct, sys, time

def csum(b):
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return ~t & 0xffff

p = argparse.ArgumentParser()
p.add_argument("-t", type=float, default=2.0)
p.add_argument("ifs", nargs="+")
a = p.parse_args()
socks = {}
for i in a.ifs:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((i, 0))
    socks[s.fileno()] = (s, i)
end = time.monotonic() + a.t
print("ready", flush=True)
while True:
    left = end - time.monotonic()
    if left <= 0: break
    r, _, _ = select.select(list(socks), [], [], left)
    for fd in r:
        s, name = socks[fd]
        d, addr = s.recvfrom(65535)
        if addr[2] == 4: continue            # PACKET_OUTGOING
        if addr[3] == 1 and len(d) >= 14 and d[12:14] == b"\x08\x00": ip = d[14:]; mac = (d[6:12].hex(), d[0:6].hex())
        elif addr[3] != 1 and len(d) >= 20 and d[0] >> 4 == 4: ip = d; mac = ("-", "-")
        else: continue
        ihl = (ip[0] & 15) * 4
        tos = ip[1]; tl = struct.unpack("!H", ip[2:4])[0]; ttl = ip[8]; pr = ip[9]
        src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
        sp = dp = 0
        if pr in (6, 17): sp, dp = struct.unpack("!HH", ip[ihl:ihl + 4])
        print(name, mac[0], mac[1], src, dst, pr, sp, dp, ttl, tos, tl, int(csum(ip[:ihl]) == 0), ip[ihl + 8:ihl + 16].hex(), flush=True)
