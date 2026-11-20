#!/usr/bin/env python3
"""Test helper for tests/test-dedup.sh: sends crafted IPv4 frames on lo.

  dedup-send.py --lo-up
      bring lo up and allow 127/8 sources arriving on it (route_localnet),
      in a fresh network namespace
  dedup-send.py [--recv PORT] PKT [PKT ...]
      PKT is a comma-separated list of key=value (all optional):
        proto=udp|tcp|icmp|<n>  (udp)   id=<n> (1)   src=, dst= (127.0.0.2,
        127.0.0.1)   sport=, dport= (4000, 5000)   data=<text> (x)
        df=0|1 (0)   mf=0|1 (0)   off=<fragment offset, 8-byte units> (0)
        wait=<ms before the next packet> (2)   repeat=<n> (1)
      Frames go out through an AF_PACKET socket on lo, so the IP header is
      sent exactly as given (a raw IP socket would replace ID 0). With
      --recv, a UDP socket on port PORT counts what arrives; the count
      is printed at the end.
"""
import errno, fcntl, socket, struct, sys, time

def lo_up():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    flags = struct.unpack('16sH14x', fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack('16sH14x', b'lo', 0)))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack('16sH14x', b'lo', flags | IFF_UP))
    # Frames sent with AF_PACKET arrive without a route: a 127/8 source is
    # martian unless route_localnet is on.
    for c in ('all', 'lo'):
        with open('/proc/sys/net/ipv4/conf/%s/route_localnet' % c, 'w') as f:
            f.write('1')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def frame(o):
    proto = {'udp': 17, 'tcp': 6, 'icmp': 1}.get(o.get('proto', 'udp'))
    if proto is None:
        proto = int(o['proto'])
    src, dst = o.get('src', '127.0.0.2'), o.get('dst', '127.0.0.1')
    sport, dport = int(o.get('sport', 4000)), int(o.get('dport', 5000))
    data = o.get('data', 'x').encode()
    ph = lambda n: socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, proto, n)
    if proto == 17:
        l4 = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
        c = csum(ph(len(l4)) + l4) or 0xffff
        l4 = l4[:6] + struct.pack('!H', c) + l4[8:]
    elif proto == 6:
        l4 = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + data
        l4 = l4[:16] + struct.pack('!H', csum(ph(len(l4)) + l4)) + l4[18:]
    elif proto == 1:
        l4 = struct.pack('!BBHHH', 13, 0, 0, 1, 1) + data      # timestamp request
        l4 = l4[:2] + struct.pack('!H', csum(l4)) + l4[4:]
    else:
        l4 = data
    flags = (0x4000 if o.get('df', '0') == '1' else 0) | (0x2000 if o.get('mf', '0') == '1' else 0)
    flags |= int(o.get('off', 0))
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), int(o.get('id', 1), 0), flags, 64,
                     proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\0' * 12 + b'\x08\x00' + ip + l4

def main(a):
    if a == ['--lo-up']:
        lo_up()
        return
    recv = None
    if a[:1] == ['--recv']:
        recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(('', int(a[1])))
        recv.setblocking(False)
        a = a[2:]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('lo', 0))
    for p in a:
        o = dict(kv.split('=', 1) for kv in p.split(',') if kv)
        for _ in range(int(o.get('repeat', 1))):
            try:
                s.send(frame(o))
            except OSError as e:          # dropped by the TC egress program
                if e.errno != errno.ENOBUFS:
                    raise
            time.sleep(int(o.get('wait', 2)) / 1000)
    if recv is not None:
        time.sleep(0.1)
        n = 0
        while True:
            try:
                recv.recv(65535)
                n += 1
            except BlockingIOError:
                break
        print(n)

if __name__ == '__main__':
    main(sys.argv[1:])
