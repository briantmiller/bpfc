#!/usr/bin/env python3
"""Test helper: send or receive UDP datagrams whose contents can be checked.

    udp-verify.py send <host> <port> <count> <rate-pps> [size]
    udp-verify.py recv <port> <seconds>

Each datagram carries its number and a SHA-256 of its random payload. The
receiver prints: received <n> distinct <n> corrupt <n> (corrupt = content
that does not match its hash, e.g. a badly rebuilt or truncated packet).
"""
import hashlib
import os
import socket
import struct
import sys
import time


def send(host, port, count, pps, size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gap = 1.0 / pps
    t = time.monotonic()
    for i in range(count):
        body = os.urandom(size - 36)
        s.sendto(struct.pack("!I", i) + hashlib.sha256(body).digest() + body, (host, port))
        t += gap
        d = t - time.monotonic()
        if d > 0:
            time.sleep(d)


def recv(port, seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    s.bind(("0.0.0.0", port))
    s.settimeout(0.5)
    end = time.monotonic() + seconds
    got, seen, bad = 0, set(), 0
    while time.monotonic() < end:
        try:
            d, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        got += 1
        if len(d) < 36 or hashlib.sha256(d[36:]).digest() != d[4:36]:
            bad += 1
            continue
        seen.add(struct.unpack("!I", d[:4])[0])
    print("received %d distinct %d corrupt %d" % (got, len(seen), bad))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["send"] and len(a) >= 5:
        send(a[1], int(a[2]), int(a[3]), float(a[4]), int(a[5]) if len(a) > 5 else 1400)
    elif a[:1] == ["recv"] and len(a) == 3:
        recv(int(a[1]), float(a[2]))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
