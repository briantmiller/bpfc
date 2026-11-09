#!/bin/bash
#
# The XDP examples in dist/examples/xdp (README "Advanced Examples" 6-12), run
# as they are, and the fib-lookup options they rely on.
#
#   bash tests/test-xdp-examples.sh
#
#   H1 h1 10.1.0.2 ---- r1 10.1.0.1   R   r2 10.2.0.1 ---- n1 10.2.0.2 N1
#                                         r3 10.3.0.1 ---- n2 10.3.0.2 N2
#   R routes 10.9.9.0/24 over both N1 and N2 (multipath), table 100 has 10.7.0.0/24 via N1.
#
# Hosts send with tx checksum offload off, so checksums are real on the wire.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root xdp-examples
require_cmds xdp-examples ip ping nc tcpdump ethtool nstat python3
TOP=$PWD
BPFC=$TOP/bpfc
EX=$TOP/dist/examples/xdp
[ -x "$BPFC" ] || { test_fail "xdp-examples (bpfc not built: make)"; tests_exit; }
T=$(mktemp -d /tmp/bpfc-xdpex.XXXXXX)
NS="H1 R N1 N2 C L"
cleanup() {
	for n in $NS; do ip netns del xe$n 2>/dev/null; done
	umount "$T/m" 2>/dev/null
	rm -rf "$T"
	rm -f "$TESTS_FAILED_FILE"
}
trap cleanup EXIT
ulimit -l unlimited

for n in $NS; do ip netns del xe$n 2>/dev/null; ip netns add xe$n; ip -n xe$n link set lo up
	ip netns exec xe$n sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null; done
H1="ip netns exec xeH1"; R="ip netns exec xeR"; N1="ip netns exec xeN1"; N2="ip netns exec xeN2"
ip link add r1 netns xeR type veth peer name h1 netns xeH1
ip link add r2 netns xeR type veth peer name n1 netns xeN1
ip link add r3 netns xeR type veth peer name n2 netns xeN2
ip -n xeH1 addr add 10.1.0.2/24 dev h1; ip -n xeR addr add 10.1.0.1/24 dev r1
ip -n xeR addr add 10.2.0.1/24 dev r2;  ip -n xeN1 addr add 10.2.0.2/24 dev n1
ip -n xeR addr add 10.3.0.1/24 dev r3;  ip -n xeN2 addr add 10.3.0.2/24 dev n2
for x in "xeH1 h1" "xeR r1" "xeR r2" "xeR r3" "xeN1 n1" "xeN2 n2"; do set -- $x
	ip -n $1 link set $2 up; ip netns exec $1 ethtool -K $2 tx off >/dev/null 2>&1; done
ip -n xeH1 route add default via 10.1.0.1
ip -n xeN1 route add default via 10.2.0.1; ip -n xeN2 route add default via 10.3.0.1
$R sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
for i in r1 r2 r3; do $R sysctl -qw net.ipv4.conf.$i.rp_filter=0; done
# N1 and N2 also answer for the multipath subnet and for 10.7.0.0/24
for n in xeN1 xeN2; do ip -n $n addr add 10.9.9.1/32 dev lo; ip -n $n addr add 10.7.0.5/32 dev lo; done
$H1 ping -c1 -W2 10.2.0.2 >/dev/null; $H1 ping -c1 -W2 10.3.0.2 >/dev/null   # resolve neighbours
H1_MAC=$(ip -n xeH1 -br link show h1 | awk '{print $3}'); R1_MAC=$(ip -n xeR -br link show r1 | awk '{print $3}')

fwd() { $R nstat -az IpForwDatagrams | awk '$1 == "IpForwDatagrams" {print $2}'; }
rxp() { ip netns exec "$1" cat /sys/class/net/$2/statistics/rx_packets; }
attach() { # attach <program file> [bpfc options] on r1, r2 and r3
	local f=$1; shift
	for i in r1 r2 r3; do $R "$BPFC" -i $i -d xdp "$@" -f "$EX/$f" >"$T/out" 2>&1 || { cat "$T/out" | head -3; return 1; }; done
}
detach() { for i in r1 r2 r3; do $R "$BPFC" -i $i -d xdp -D; done; }
# udp_flows <count> <first sport> [src address]: one datagram per source port from H1 to 10.9.9.1
udp_flows() {
	$H1 python3 - "$@" <<-'EOF'
	import socket, sys
	n, p = int(sys.argv[1]), int(sys.argv[2])
	src = sys.argv[3] if len(sys.argv) > 3 else "10.1.0.2"
	for i in range(n):
	    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	    s.bind((src, p + i)); s.sendto(b"x", ("10.9.9.1", 9)); s.close()
	EOF
}
# count <ns> <dev> <filter> <seconds> <command...>: packets matching filter on dev while command runs
count() {
	local ns=$1 dev=$2 f=$3 secs=$4; shift 4
	rm -f "$T/c.out" "$T/c.err"
	ip netns exec $ns timeout $secs tcpdump -nn -i $dev "$f" > "$T/c.out" 2>"$T/c.err" & local p=$!
	for _ in $(seq 50); do grep -q "listening on" "$T/c.err" 2>/dev/null && break; sleep 0.1; done
	sleep 0.2; "$@" >/dev/null 2>&1; wait $p 2>/dev/null
	grep -c . "$T/c.out"
}

echo "the README shows the example files as they are"
for f in "$EX"/*.bpfc; do
	check "XDP-example-in-README-$(basename "$f" .bpfc)" python3 -c '
import sys; sys.exit(open(sys.argv[1]).read().rstrip("\n") not in open(sys.argv[2]).read())' "$f" "$TOP/README.md"
done
printf 'include urpf.bpfc;\ninclude router.bpfc;\n' > "$EX/.urpf-router.bpfc"
check XDP-example-urpf-plus-router eval '$R "$BPFC" -i r1 -d xdp -f "$EX/.urpf-router.bpfc" >/dev/null'
rm -f "$EX/.urpf-router.bpfc"; $R "$BPFC" -i r1 -d xdp -D

echo "router.bpfc: forwarding in XDP"
attach router.bpfc || test_fail "router attach"
f0=$(fwd)
$N1 timeout 4 tcpdump -nvv -i n1 -c 3 icmp > "$T/rt.cap" 2>/dev/null & cap=$!; sleep 1
check XDP-router-ping eval '$H1 ping -q -c 20 -i 0.05 -W1 10.2.0.2 >/dev/null'
wait $cap
check XDP-router-not-kernel   eval '[ $(( $(fwd) - f0 )) -eq 0 ]'
check XDP-router-ttl          grep -q "ttl 63" "$T/rt.cap"
check XDP-router-ip-checksum  eval '! grep -q "bad cksum" "$T/rt.cap"'
head -c 300000 /dev/urandom > "$T/src"; f0=$(fwd)
$N1 timeout 6 nc -l 10.2.0.2 7000 > "$T/dst" & sleep 0.5
$H1 timeout 5 nc --send-only 10.2.0.2 7000 < "$T/src"; wait
check XDP-router-tcp          cmp -s "$T/src" "$T/dst"
check XDP-router-tcp-not-kernel eval '[ $(( $(fwd) - f0 )) -eq 0 ]'
check XDP-router-ttl-expired  eval '$H1 ping -c1 -W1 -t 1 10.2.0.2 | grep -qi "time to live exceeded"'
# an unresolved neighbour: the kernel forwards (and resolves it), then XDP takes over
ip -n xeR neigh flush dev r2; f0=$(fwd)
$H1 ping -c 5 -i 0.2 -W1 10.2.0.2 >/dev/null
check XDP-router-neigh-fallback eval 'k=$(( $(fwd) - f0 )); [ $k -ge 1 ] && [ $k -lt 10 ]'

echo "multipath: 10.9.9.0/24 over N1 and N2"
ip -n xeR route add 10.9.9.0/24 nexthop via 10.2.0.2 dev r2 nexthop via 10.3.0.2 dev r3
for a in $(seq 10 41); do ip -n xeH1 addr add 10.1.0.$a/24 dev h1; done
# R learns those sources' neighbours, so replies to them are not neighbour misses (which go to the kernel)
for a in $(seq 10 41); do $H1 ping -c1 -W1 -I 10.1.0.$a 10.1.0.1 >/dev/null; done
spread() { # spread <cmd...>: packets arriving at N1 and N2 while cmd runs -> "n1 n2"
	local a1 a2; a1=$(rxp xeN1 n1); a2=$(rxp xeN2 n2); "$@"; sleep 0.5
	echo "$(( $(rxp xeN1 n1) - a1 )) $(( $(rxp xeN2 n2) - a2 ))"
}
both() { set -- $1; [ "$1" -gt 0 ] && [ "$2" -gt 0 ]; }
one()  { set -- $1; [ "$1" -eq 0 ] || [ "$2" -eq 0 ]; }
many_sources() { for a in $(seq 10 41); do udp_flows 1 5000 10.1.0.$a; done; }
$R sysctl -qw net.ipv4.fib_multipath_hash_policy=0
f0=$(fwd); s=$(spread many_sources)
check XDP-multipath-l3-spreads    both "$s"
check XDP-multipath-l3-in-xdp     eval '[ $(( $(fwd) - f0 )) -eq 0 ]'
$R sysctl -qw net.ipv4.fib_multipath_hash_policy=1
s=$(spread udp_flows 64 20000)
check XDP-multipath-l4-needs-flow one  "$s"
attach router.bpfc -s FLOW=1 || test_fail "router FLOW=1 attach"
f0=$(fwd); s=$(spread udp_flows 64 20000)
check XDP-multipath-l4-flow-spreads both "$s"
check XDP-multipath-l4-in-xdp     eval '[ $(( $(fwd) - f0 )) -eq 0 ]'
s=$(spread udp_flows 1 20007); s2=$(spread udp_flows 1 20007); s3=$(spread udp_flows 1 20007)
check XDP-multipath-flow-sticks   eval '[ "$s" = "$s2" ] && [ "$s2" = "$s3" ]'
# the same choice as the kernel's own forwarding for the same flows
detach; k=$(spread udp_flows 64 30000); attach router.bpfc -s FLOW=1; x=$(spread udp_flows 64 30000)
check XDP-multipath-same-as-kernel eval '[ "$k" = "$x" ]'
# nexthop objects: a weighted group (1:3), then a resilient one
ip -n xeR route del 10.9.9.0/24
ip -n xeR nexthop add id 1 via 10.2.0.2 dev r2; ip -n xeR nexthop add id 2 via 10.3.0.2 dev r3
ip -n xeR nexthop add id 10 group 1/2,3; ip -n xeR route add 10.9.9.0/24 nhid 10
s=$(spread udp_flows 256 40000)
check XDP-multipath-weighted      eval 'set -- $s; [ $1 -gt 0 ] && [ $2 -gt $(( $1 * 3 / 2 )) ]'
ip -n xeR route del 10.9.9.0/24; ip -n xeR nexthop del id 10
ip -n xeR nexthop add id 11 group 1/2 type resilient buckets 32 idle_timer 0; ip -n xeR route add 10.9.9.0/24 nhid 11
s=$(spread udp_flows 64 50000)
check XDP-multipath-resilient     both "$s"
ip -n xeR route del 10.9.9.0/24; ip -n xeR nexthop flush >/dev/null
$R sysctl -qw net.ipv4.fib_multipath_hash_policy=0
detach

echo "fib-lookup options"
mkdir -p "$T/m"; mount -t bpf bpffs "$T/m"
fprog() { # fprog <options>: forward what the lookup resolves, drop the rest
	echo "match ip; decl D 4; get ip-dst D; fib-lookup $1 %D; match val %FIB_RESULT eq 0; set dst-mac %FIB_DMAC; set src-mac %FIB_SMAC; redirect %FIB_IFINDEX; end-match; drop; end-match"
}
ip -n xeR route add 10.7.0.0/24 via 10.2.0.2 dev r2 table 100
$R "$BPFC" -i r1 -d xdp "$(fprog '')" >/dev/null
check XDP-fib-main-no-route   eval '[ $(count xeN1 n1 "icmp and host 10.7.0.5" 3 $H1 ping -c 3 -i 0.2 -W1 10.7.0.5) -eq 0 ]'
$R "$BPFC" -i r1 -d xdp "$(fprog 'tbid 100')" >/dev/null
check XDP-fib-tbid            eval '[ $(count xeN1 n1 "icmp and host 10.7.0.5" 3 $H1 ping -c 3 -i 0.2 -W1 10.7.0.5) -ge 3 ]'
ip -n xeR rule add from 10.1.0.99 lookup 100 pref 100
$R "$BPFC" -i r1 -d xdp "$(fprog 'src 10.1.0.99')" >/dev/null
check XDP-fib-src-rule        eval '[ $(count xeN1 n1 "icmp and host 10.7.0.5" 3 $H1 ping -c 3 -i 0.2 -W1 10.7.0.5) -ge 3 ]'
$R "$BPFC" -i r1 -d xdp "$(fprog 'direct src 10.1.0.99')" >/dev/null
check XDP-fib-direct-skips-rules eval '[ $(count xeN1 n1 "icmp and host 10.7.0.5" 3 $H1 ping -c 3 -i 0.2 -W1 10.7.0.5) -eq 0 ]'
ip -n xeR rule del pref 100; ip -n xeR route flush table 100; $R "$BPFC" -i r1 -d xdp -D
flags_of() { # the flags argument (R4) of the fib_lookup call in a compiled program
	(cd "$T" && "$BPFC" -m "$T/m" "$1" >/dev/null 2>&1 && python3 -c '
import struct; d = open("output.bpf", "rb").read(); r4 = None
for i in range(0, len(d), 8):
    c, r, o, imm = struct.unpack("<BBhi", d[i:i + 8])
    if c == 0xb7 and r & 15 == 4: r4 = imm
    if c == 0x85 and imm == 69: print(r4); break')
}
check XDP-fib-flag-direct     eval '[ "$(flags_of "fib-lookup direct 10.0.0.1")" = 1 ]'
check XDP-fib-flag-output     eval '[ "$(flags_of "fib-lookup output 10.0.0.1")" = 2 ]'
check XDP-fib-flag-skip-neigh eval '[ "$(flags_of "fib-lookup skip-neigh 10.0.0.1")" = 4 ]'
check XDP-fib-flag-tbid       eval '[ "$(flags_of "fib-lookup tbid 7 10.0.0.1")" = 9 ]'
check XDP-fib-flag-src        eval '[ "$(flags_of "fib-lookup src")" = 16 ]'
check XDP-fib-tbid-needs-table eval '! "$BPFC" "fib-lookup tbid 10.0.0.1" 2>&1 | grep -q Compiled'
check XDP-fib-mark-refused    eval '"$BPFC" "fib-lookup mark 10.0.0.1" 2>&1 | grep -q "not supported"'

echo "mss-clamp.bpfc"
attach mss-clamp.bpfc || test_fail "mss attach"
mss_seen() { # mss_seen <h1 mtu>: the MSS N1 receives in H1's SYN, and its checksum state
	ip -n xeH1 link set h1 mtu $1
	$N1 timeout 4 tcpdump -nvv -i n1 -c 1 "tcp[tcpflags] & tcp-syn != 0 and dst port 7001" > "$T/mss" 2>/dev/null & local c=$!; sleep 1
	$N1 timeout 3 nc -l 10.2.0.2 7001 >/dev/null & sleep 0.3
	echo hi | $H1 timeout 2 nc --send-only 10.2.0.2 7001 >/dev/null 2>&1; wait $c; wait
	echo "$(grep -o 'mss [0-9]*' "$T/mss") $(grep -o '(correct)\|(incorrect' "$T/mss" | head -1)"
	ip -n xeH1 link set h1 mtu 1500
}
check XDP-mss-clamped     eval '[ "$(mss_seen 1500)" = "mss 1360 (correct)" ]'
check XDP-mss-kept        eval '[ "$(mss_seen 1240)" = "mss 1200 (correct)" ]'
detach

echo "urpf.bpfc"
spoof() { # spoof <source>: ICMP from H1 to N1 with that source; prints how many N1 sees
	count xeN1 n1 "icmp and src $1" 3 $H1 python3 -c "
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import Ether, IP, ICMP, sendp
sendp(Ether(src='$H1_MAC', dst='$R1_MAC') / IP(src='$1', dst='10.2.0.2') / ICMP(), iface='h1', count=3, verbose=0)"
}
for i in r1 r2 r3; do $R sysctl -qw net.ipv4.conf.$i.forwarding=1; done
attach urpf.bpfc || test_fail "urpf attach"
check XDP-urpf-legit          eval '[ $(spoof 10.1.0.2) -ge 3 ]'
check XDP-urpf-strict-spoof   eval '[ $(spoof 10.3.0.77) -eq 0 ]'
check XDP-urpf-no-route       eval '[ $(spoof 192.0.2.1) -eq 0 ]'
check XDP-urpf-own-address    eval '[ $(spoof 10.2.0.1) -eq 0 ]'
attach urpf.bpfc -s LOOSE=1 || test_fail "urpf loose attach"
check XDP-urpf-loose-spoof    eval '[ $(spoof 10.3.0.77) -ge 3 ]'
check XDP-urpf-loose-no-route eval '[ $(spoof 192.0.2.1) -eq 0 ]'
detach

echo "dsr-lb.bpfc: client C, load balancer L (tx back to the backends' segment)"
ip link add l0 netns xeL type veth peer name c0 netns xeC
ip -n xeL link set l0 up; ip -n xeC link set c0 up
L0_MAC=$(ip -n xeL -br link show l0 | awk '{print $3}')
ip netns exec xeL "$BPFC" -i l0 -d xdp -f "$EX/dsr-lb.bpfc" >/dev/null || test_fail "dsr-lb attach"
syns() { # syns <first sport> <count>: SYNs from C to the VIP
	ip netns exec xeC python3 -c "
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, sendp
sendp([Ether(dst='$L0_MAC') / IP(src='10.9.0.2', dst='10.9.0.100') / TCP(sport=p, dport=80, flags='S') for p in range($1, $1 + $2)], iface='c0', verbose=0)"
}
ip netns exec xeC timeout 5 tcpdump -enn -i c0 -Q in "tcp dst port 80" > "$T/lb" 2>"$T/lb.err" & cap=$!
for _ in $(seq 50); do grep -q "listening on" "$T/lb.err" 2>/dev/null && break; sleep 0.1; done
sleep 0.2; syns 30000 60; syns 31000 1; syns 31000 1; syns 31000 1; wait $cap
backends=$(grep -o "> 02:00:00:00:00:a[0-2]" "$T/lb" | sort -u | wc -l)
check XDP-dsr-all-backends    eval '[ "$backends" = 3 ]'
check XDP-dsr-src-is-lb       eval 'grep "02:00:00:00:00:a" "$T/lb" | grep -qi "^[^ ]* $L0_MAC >"'
check XDP-dsr-flow-sticks     eval '[ $(grep "\.31000 >" "$T/lb" | grep -o "> 02:00:00:00:00:a[0-2]" | sort -u | wc -l) -eq 1 ]'

echo "vlan-translate.bpfc, size-histogram.bpfc, syn-guard.bpfc (on L, frames from C)"
L="ip netns exec xeL"
lsend() { ip netns exec xeC python3 -c "
import logging; logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
sendp($1, iface='c0', verbose=0)"; }
$L "$BPFC" -i l0 -d xdp -L "$EX" "include vlan-translate.bpfc; tx" >/dev/null || test_fail "vlan attach"
ip netns exec xeC timeout 4 tcpdump -enn -i c0 -Q in vlan > "$T/vl" 2>"$T/vl.err" & cap=$!
for _ in $(seq 50); do grep -q "listening on" "$T/vl.err" 2>/dev/null && break; sleep 0.1; done
sleep 0.2
lsend "[Ether(dst='$L0_MAC')/Dot1Q(vlan=v, prio=5)/IP(dst='10.0.0.1')/ICMP() for v in (100, 105, 109, 110)]"
wait $cap
check XDP-vlan-translate-100  grep -q "vlan 2000, p 5" "$T/vl"
check XDP-vlan-translate-105  grep -q "vlan 2005, p 5" "$T/vl"
check XDP-vlan-translate-109  grep -q "vlan 2009, p 5" "$T/vl"
check XDP-vlan-translate-other grep -q "vlan 110, p 5" "$T/vl"

$L "$BPFC" -i l0 -d xdp -m "$T/m" -f "$EX/size-histogram.bpfc" >/dev/null || test_fail "histogram attach"
lsend "[Ether(dst='$L0_MAC')/IP(dst='10.0.0.1')/UDP()/Raw(b'x' * n) for n in (10, 10, 60, 950, 950, 950)]"
hist() { local v; v=$("$BPFC" -m "$T/m" -r SIZES_l0 | awk -v k=$(printf "0x%016x" $1) '$3 == k {print $6}'); echo $(( ${v:-0} )); }
check XDP-histogram-64        eval '[ "$(hist 0)" = 2 ]'
check XDP-histogram-128       eval '[ "$(hist 1)" = 1 ]'
check XDP-histogram-1024      eval '[ "$(hist 4)" = 3 ]'

$L "$BPFC" -i l0 -d xdp -m "$T/m" -s LIMIT=5 -f "$EX/syn-guard.bpfc" >/dev/null || test_fail "syn-guard attach"
syns_from() { # syns_from <source> <count>: SYNs from that source; prints how many pass the program
	count xeL l0 "tcp[tcpflags] & tcp-syn != 0 and src $1" 3 lsend "[Ether(dst='$L0_MAC')/IP(src='$1', dst='10.0.0.1')/TCP(sport=40000+i, dport=22, flags='S') for i in range($2)]"
}
# 5 per window; a burst that happens to cross a window boundary gets up to 10
check XDP-syn-guard-limit     eval 'n=$(syns_from 10.9.0.7 20); [ $n -ge 5 ] && [ $n -le 10 ]'
check XDP-syn-guard-other-src eval '[ $(syns_from 10.9.0.8 3) -eq 3 ]'

tests_exit
