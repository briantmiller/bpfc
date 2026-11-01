#!/usr/bin/env python3
"""Test helper: bridge two interfaces with a fixed one-way delay.

    link-emulator.py <if-a> <if-b> <delay-ms>

Frames received on one interface are sent out of the other <delay-ms> later,
in order, in both directions (a long-delay link such as a GEO satellite hop,
for test-dataplane.sh). Frames we transmit ourselves are ignored. Runs until
killed. Python is used only by the tests; the dataplane itself is bpfc.

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


def forward(rx, tx, delay):
    queue = collections.deque()
    cv = threading.Condition()

    def sender():
        while True:
            with cv:
                while not queue:
                    cv.wait()
                due, frame = queue[0]
            wait = due - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            with cv:
                queue.popleft()
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
        with cv:
            queue.append((time.monotonic() + delay, frame))
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
        print("emulator drops: rx %s %d / %s %d, tx %s %d / %s %d" % (
            names[0], total[names[0]], names[1], total[names[1]],
            names[0], send_errors[a.fileno()], names[1], send_errors[b.fileno()]),
            file=sys.stderr, flush=True)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    a, b = open_if(sys.argv[1]), open_if(sys.argv[2])
    delay = float(sys.argv[3]) / 1000.0
    threading.Thread(target=report, args=(a, b, sys.argv[1:3]), daemon=True).start()
    threading.Thread(target=forward, args=(a, b, delay), daemon=True).start()
    forward(b, a, delay)


if __name__ == "__main__":
    main()
