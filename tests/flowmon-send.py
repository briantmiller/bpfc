#!/usr/bin/env python3
"""Test helper for tests/test-flowmon.sh: sends crafted TCP data segments.

  flowmon-send.py --lo-up
      bring the loopback device up (in a fresh network namespace)
  flowmon-send.py SRC SPORT DST DPORT SEQ LEN [+MS] [SEQ LEN [+MS]] ...
      send each segment (PSH|ACK, LEN bytes of payload) with a raw socket;
      +MS waits MS milliseconds before the next one (default 2 ms)
"""
import fcntl, socket, struct, sys, time

def lo_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    req = struct.pack('16sH14x', b'lo', 0)
    flags = struct.unpack('16sH14x', fcntl.ioctl(s, SIOCGIFFLAGS, req))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack('16sH14x', b'lo', flags | IFF_UP))

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def segment(src, sport, dst, dport, seq, n):
    pay = b'x' * n
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, 1, 5 << 4, 0x18, 65535, 0, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(tcp) + n)
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + pay)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + n, 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + tcp + pay

def main(a):
    if a == ['--lo-up']:
        lo_up()
        return
    src, sport, dst, dport = a[0], int(a[1]), a[2], int(a[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    i = 4
    while i + 1 < len(a):
        s.sendto(segment(src, sport, dst, dport, int(a[i], 0), int(a[i + 1], 0)), (dst, 0))
        i += 2
        wait = 2
        if i < len(a) and a[i].startswith('+'):
            wait = int(a[i][1:])
            i += 1
        time.sleep(wait / 1000)

main(sys.argv[1:])
