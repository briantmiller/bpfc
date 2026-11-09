#!/usr/bin/env python3
"""
Frames for test-xdp.sh's resizing checks: an XDP program on the DUT changes
each frame and redirects it to the sniffer, which compares the bytes.

  xdp-resize.py sniff <iface> <out> <ready>   write the first frame (hex) to <out>
  xdp-resize.py send <iface> <case>           send the case's frame
  xdp-resize.py check <case> <out>            exit 0 if the frame is what the case expects
"""
import os
import sys
import time

from scapy.all import Ether, Dot1Q, IP, UDP, GRE, Raw, sendp, sniff, conf  # noqa: E402
from scapy.contrib.mpls import MPLS  # noqa: E402

conf.verb = 0
SRC, DST = "02:00:00:00:00:01", "02:00:00:00:00:02"
NS, ND = "02:00:00:00:00:aa", "02:00:00:00:00:bb"   # MACs the programs write
# pw-encap: the MACs fib-lookup finds on the DUT (test-xdp.sh passes them)
FS, FD = os.environ.get("FIB_SMAC", NS), os.environ.get("FIB_DMAC", ND)
PAY = bytes(range(64)) * 3                          # 192 recognisable bytes


def ip():
    return IP(src="10.9.0.2", dst="10.8.0.2", ttl=33) / UDP(sport=1111, dport=4444) / Raw(PAY)


def inner():
    return Ether(src=SRC, dst=DST) / ip()


def mpls_word(label, bos, ttl):
    return ((label << 12) | (bos << 8) | ttl).to_bytes(4, "big")


# case -> (frame to send, expected frame bytes)
CASES = {
    "encap-mpls": (inner(), bytes(Ether(src=SRC, dst=DST, type=0x8847)) + mpls_word(16, 1, 64) + bytes(ip())),
    "decap-mpls": (Ether(src=SRC, dst=DST, type=0x8847) / MPLS(label=16, s=1, ttl=9) / ip(), bytes(inner())),
    "decap-mpls-cw": (Ether(src=SRC, dst=DST, type=0x8847) / MPLS(label=16, s=1, ttl=9) / Raw(b"\0\0\0\0") / ip(),
                      bytes(inner())),
    # README / test-mpls.sh pseudowire: next-hop label 20, PW label 16, whole Ethernet frame inside
    "pw-encap": (inner(), bytes(Ether(src=FS, dst=FD, type=0x8847)) + mpls_word(20, 0, 225) + mpls_word(16, 1, 225)
                 + bytes(inner())),
    "pw-encap-cw": (inner(), bytes(Ether(src=FS, dst=FD, type=0x8847)) + mpls_word(20, 0, 225) + mpls_word(16, 1, 225)
                    + b"\0\0\0\0" + bytes(inner())),
    "pw-decap": (Ether(src=NS, dst=ND, type=0x8847) / MPLS(label=16, s=1, ttl=225) / inner(), bytes(inner())),
    "pw-decap-cw": (Ether(src=NS, dst=ND, type=0x8847) / MPLS(label=16, s=1, ttl=225) / Raw(b"\0\0\0\0") / inner(),
                    bytes(inner())),
    "add-l2-bytes": (inner(), bytes(inner())[:14] + b"\0" * 20 + bytes(inner())[14:]),
    "add-bytes-far": (inner(), bytes(inner())[:100] + b"\0" * 4 + bytes(inner())[100:]),
    "del-bytes-far": (inner(), bytes(inner())[:100] + bytes(inner())[104:]),
    "add-bytes-near": (inner(), bytes(inner())[:20] + b"\0" * 6 + bytes(inner())[20:]),
    "del-bytes-near": (inner(), bytes(inner())[:20] + bytes(inner())[26:]),
    "push-vlan": (inner(), bytes(Ether(src=SRC, dst=DST) / Dot1Q(vlan=100, prio=3) / ip())),
    "pop-vlan": (Ether(src=SRC, dst=DST) / Dot1Q(vlan=100) / ip(), bytes(inner())),
    "push-qinq": (inner(), bytes(Ether(src=SRC, dst=DST, type=0x88A8) / Dot1Q(vlan=10, type=0x8100) / Dot1Q(vlan=20)
                                 / ip())),
    "push-eth": (inner(), bytes(Ether(src=NS, dst=ND, type=0x0800)) + bytes(inner())),
    "pop-eth": (Ether(src=NS, dst=ND) / inner(), bytes(inner())),
    "set-len": (inner(), bytes(inner())[:80]),
    "decap-gre": (Ether(src=SRC, dst=DST) / IP(src="1.1.1.1", dst="2.2.2.2", proto=47) / GRE(proto=0x0800) / ip(),
                  bytes(inner())),
}
# VLAN id in the frame's tag: priority and DEI stay; no tag: an 802.1Q tag is pushed
def tagged(vid, prio=5, tpid=0x8100):
    return Ether(src=SRC, dst=DST, type=tpid) / Dot1Q(vlan=vid, prio=prio, id=1) / ip()


CASES.update({
    "set-vlan-id": (tagged(100), bytes(tagged(200))),
    "set-vlan-id-var": (tagged(100), bytes(tagged(201))),
    "set-vlan-id-qinq": (tagged(100, tpid=0x88A8), bytes(tagged(200, tpid=0x88A8))),
    "set-vlan-id-untagged": (inner(), bytes(Ether(src=SRC, dst=DST) / Dot1Q(vlan=200, prio=0) / ip())),
    "match-vlan-id": (tagged(100), bytes(tagged(300))),
    "match-vlan-id-miss": (tagged(50), bytes(tagged(50))),
    "match-vlan-id-var": (tagged(100), bytes(tagged(300))),
    "match-vlan-id-range": (tagged(15), bytes(tagged(300))),
    "match-vlan-id-untagged": (inner(), bytes(inner())),
})

# pw-encap with a next hop fib-lookup cannot resolve: the frame is not encapsulated
CASES["pw-encap-miss"] = (inner(), bytes(inner()))

# del-l2-bytes: 4 bytes after the Ethernet header go, the EtherType stays what it was
_del = Ether(src=SRC, dst=DST, type=0x0800) / Raw(b"\xee" * 4) / ip()
CASES["del-l2-bytes"] = (_del, bytes(inner()))


def main():
    mode = sys.argv[1]
    if mode == "sniff":
        iface, out, ready = sys.argv[2:5]
        res = sniff(iface=iface, count=1, timeout=6, lfilter=lambda p: p.haslayer(Ether) and p[Ether].type != 0x86DD,
                    started_callback=lambda: open(ready, "w").close())
        with open(out, "w") as f:
            # the bytes as received: re-serialising (bytes(pkt)) rebuilds fields of a broken header
            f.write(bytes(res[0].original).hex() if res else "")
    elif mode == "send":
        iface, case = sys.argv[2:4]
        time.sleep(0.2)
        sendp(CASES[case][0], iface=iface)
    elif mode == "check":
        case, out = sys.argv[2:4]
        got = bytes.fromhex(open(out).read().strip() or "")
        want = CASES[case][1]
        if got != want:
            print(f"    got  {got[:64].hex()}{'...' if len(got) > 64 else ''} ({len(got)} bytes)")
            print(f"    want {want[:64].hex()}{'...' if len(want) > 64 else ''} ({len(want)} bytes)")
            for i, (a, b) in enumerate(zip(got, want)):
                if a != b:
                    print(f"    first difference at byte {i}")
                    break
            sys.exit(1)


if __name__ == "__main__":
    main()
