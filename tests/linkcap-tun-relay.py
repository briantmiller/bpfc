#!/usr/bin/env python3
"""Test helper: a point-to-point raw-IP link between two network namespaces.

    linkcap-tun-relay.py <netns-a> <tun-a> <netns-b> <tun-b> [--a2b SPEC] [--b2a SPEC]

Creates tun device <tun-a> in /run/netns/<netns-a> and <tun-b> in
/run/netns/<netns-b> (IFF_TUN, no packet information) and relays IP packets
between them, so the two ends see a point-to-point link with no Ethernet
header, like GRE, PPP or WireGuard (for test-linkcap.sh). SPEC is
comma-separated key=value:
  loss=5       random loss in percent
  rate=20m     bits per second (k, m, g) of IP packets; a FIFO queue in front
  limit=100    queue limit in packets with a rate, excess is dropped
Prints "ready" on stdout once both devices exist; runs until killed.
Python is used only by the tests; linkcap itself is bpfc.
"""
import collections
import fcntl
import os
import random
import select
import struct
import sys
import threading
import time

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def parse_spec(s):
    out = {"loss": 0.0, "rate": 0.0, "limit": 100}
    if not s:
        return out
    for kv in s.split(","):
        k, v = kv.split("=")
        if k == "rate":
            m = {"k": 1e3, "m": 1e6, "g": 1e9}.get(v[-1].lower(), 1)
            out["rate"] = float(v[:-1] if m != 1 else v) * m
        elif k == "loss":
            out["loss"] = float(v)
        elif k == "limit":
            out["limit"] = int(v)
        else:
            raise SystemExit("unknown key " + k)
    return out


def open_tun(ns, name):
    here = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open("/run/netns/" + ns, os.O_RDONLY)
    os.setns(target, os.CLONE_NEWNET)
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    os.setns(here, os.CLONE_NEWNET)
    os.close(here)
    os.close(target)
    return fd


class Direction:
    def __init__(self, src, dst, spec):
        self.src, self.dst, self.spec = src, dst, spec
        self.q = collections.deque()
        self.cv = threading.Condition()
        if spec["rate"]:
            threading.Thread(target=self.sender, daemon=True).start()

    def packet(self, pkt):
        if self.spec["loss"] and random.random() * 100 < self.spec["loss"]:
            return
        if not self.spec["rate"]:
            os.write(self.dst, pkt)
            return
        with self.cv:
            if len(self.q) >= self.spec["limit"]:
                return
            self.q.append(pkt)
            self.cv.notify()

    def sender(self):
        t = time.monotonic()
        while True:
            with self.cv:
                while not self.q:
                    self.cv.wait()
                pkt = self.q.popleft()
            t = max(t, time.monotonic()) + len(pkt) * 8 / self.spec["rate"]
            d = t - time.monotonic()
            if d > 0:
                time.sleep(d)
            try:
                os.write(self.dst, pkt)
            except OSError:
                pass


def main():
    args = sys.argv[1:]
    a2b = b2a = ""
    if "--a2b" in args:
        i = args.index("--a2b"); a2b = args[i + 1]; del args[i:i + 2]
    if "--b2a" in args:
        i = args.index("--b2a"); b2a = args[i + 1]; del args[i:i + 2]
    if len(args) != 4:
        raise SystemExit(__doc__)
    fa = open_tun(args[0], args[1])
    fb = open_tun(args[2], args[3])
    dirs = {fa: Direction(fa, fb, parse_spec(a2b)), fb: Direction(fb, fa, parse_spec(b2a))}
    print("ready", flush=True)
    while True:
        r, _, _ = select.select([fa, fb], [], [])
        for f in r:
            try:
                pkt = os.read(f, 65536)
            except OSError:
                continue
            dirs[f].packet(pkt)


if __name__ == "__main__":
    main()
