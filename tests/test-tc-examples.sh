#!/bin/bash
#
# The TC examples in dist/examples/tc (README "Advanced Examples" 13-18), run
# as they are.
#
#   bash tests/test-tc-examples.sh
#
#   H1 h1 10.1.0.2 ---- r1 10.1.0.1   R   r2 10.2.0.1 ---- n1 10.2.0.2 N1   (main table: default)
#                                         r3 10.3.0.1 ---- n2 10.3.0.2 N2   (table 200: fwmark 2)
#                                         mon0 ---- m0 M                    (mirror)
#
# Hosts send with tx checksum offload off, so checksums are real on the wire.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root tc-examples
require_cmds tc-examples ip ping tcpdump ethtool tc python3
TOP=$PWD
BPFC=$TOP/bpfc
EX=$TOP/dist/examples/tc
[ -x "$BPFC" ] || { test_fail "tc-examples (bpfc not built: make)"; tests_exit; }
T=$(mktemp -d /tmp/bpfc-tcex.XXXXXX)
NS="H1 R N1 N2 M"
cleanup() {
	for n in $NS; do ip netns del te$n 2>/dev/null; done
	umount "$T/m" 2>/dev/null
	rm -rf "$T"
	rm -f "$TESTS_FAILED_FILE"
}
trap cleanup EXIT
ulimit -l unlimited 2>/dev/null

for n in $NS; do ip netns del te$n 2>/dev/null; ip netns add te$n; ip -n te$n link set lo up
	ip netns exec te$n sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null; done
H1="ip netns exec teH1"; R="ip netns exec teR"; N1="ip netns exec teN1"
ip link add r1 netns teR type veth peer name h1 netns teH1
ip link add r2 netns teR type veth peer name n1 netns teN1
ip link add r3 netns teR type veth peer name n2 netns teN2
ip link add mon0 netns teR type veth peer name m0 netns teM
ip -n teH1 addr add 10.1.0.2/24 dev h1; ip -n teR addr add 10.1.0.1/24 dev r1
ip -n teR addr add 10.2.0.1/24 dev r2;  ip -n teN1 addr add 10.2.0.2/24 dev n1
ip -n teR addr add 10.3.0.1/24 dev r3;  ip -n teN2 addr add 10.3.0.2/24 dev n2
for x in "teH1 h1" "teR r1" "teR r2" "teR r3" "teR mon0" "teM m0" "teN1 n1" "teN2 n2"; do set -- $x
	ip -n $1 link set $2 up; ip netns exec $1 ethtool -K $2 tx off >/dev/null 2>&1; done
ip -n teH1 route add default via 10.1.0.1
ip -n teN1 route add default via 10.2.0.1; ip -n teN2 route add default via 10.3.0.1
for n in teN1 teN2; do ip -n $n addr add 10.9.9.1/32 dev lo; done
$R sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
for i in r1 r2 r3; do $R sysctl -qw net.ipv4.conf.$i.rp_filter=0; done
ip -n teR route add default via 10.2.0.2
ip -n teR route add default via 10.3.0.2 table 200
ip -n teR rule add fwmark 2 table 200 pref 100
$H1 ping -c1 -W2 10.2.0.2 >/dev/null; $H1 ping -c1 -W2 10.9.9.1 >/dev/null
mkdir -p "$T/m"; mount -t bpf bpffs "$T/m"

# count <ns> <dev> <filter> <seconds> <command...>: packets matching filter on dev while command runs
count() {
	local ns=$1 dev=$2 f=$3 secs=$4; shift 4
	rm -f "$T/c.out" "$T/c.err"
	ip netns exec $ns timeout $secs tcpdump -nn -i $dev "$f" > "$T/c.out" 2>"$T/c.err" & local p=$!
	for _ in $(seq 50); do grep -q "listening on" "$T/c.err" 2>/dev/null && break; sleep 0.1; done
	sleep 0.2; "$@" >/dev/null 2>&1; wait $p 2>/dev/null
	grep -c . "$T/c.out"
}
# capture <ns> <dev> <filter> <seconds> <command...>: tcpdump -vv output while command runs
capture() {
	local ns=$1 dev=$2 f=$3 secs=$4; shift 4
	rm -f "$T/c.out" "$T/c.err"
	ip netns exec $ns timeout $secs tcpdump -nn -vv -i $dev "$f" > "$T/c.out" 2>"$T/c.err" & local p=$!
	for _ in $(seq 50); do grep -q "listening on" "$T/c.err" 2>/dev/null && break; sleep 0.1; done
	sleep 0.2; "$@" >/dev/null 2>&1; wait $p 2>/dev/null
	cat "$T/c.out"
}
udp() { # udp <addr> <port>: one datagram (python: ncat and OpenBSD nc disagree on options)
	$H1 python3 -c 'import socket,sys; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b"x",(sys.argv[1],int(sys.argv[2])))' "$@"
}
syn() { $H1 timeout 1 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null; true; }
rxb() { ip netns exec "$1" cat /sys/class/net/$2/statistics/rx_bytes; }

echo "the README shows the example files as they are"
for f in "$EX"/*.bpfc; do
	check "TC-example-in-README-$(basename "$f" .bpfc)" python3 -c '
import sys; sys.exit(open(sys.argv[1]).read().rstrip("\n") not in open(sys.argv[2]).read())' "$f" "$TOP/README.md"
done

echo "app-routing.bpfc: applications to the second uplink by fwmark"
$R "$BPFC" -i r1 -d ingress -p 10 -f "$EX/app-routing.bpfc" >/dev/null || test_fail "app-routing attach"
check TC-app-sip-uplink2     eval '[ $(count teN2 n2 "udp port 5060" 2 udp 10.9.9.1 5060) -eq 1 ]'
check TC-app-rtp-uplink2     eval '[ $(count teN2 n2 "udp port 15000" 2 udp 10.9.9.1 15000) -eq 1 ]'
check TC-app-rdp-uplink2     eval '[ $(count teN2 n2 "tcp port 3389 and tcp[tcpflags] & tcp-syn != 0" 2 syn 10.9.9.1 3389) -ge 1 ]'
check TC-app-other-uplink1   eval '[ $(count teN1 n1 "udp port 53" 2 udp 10.9.9.1 53) -eq 1 ]'
check TC-app-other-not-uplink2 eval '[ $(count teN2 n2 "udp port 53" 2 udp 10.9.9.1 53) -eq 0 ]'
$R "$BPFC" -i r1 -c

echo "dscp-classify.bpfc: on H1's egress"
$H1 "$BPFC" -i h1 -d egress -p 10 -f "$EX/dscp-classify.bpfc" >/dev/null || test_fail "dscp attach"
check TC-dscp-voice-ef       eval 'capture teN1 n1 "udp port 5060" 2 udp 10.2.0.2 5060 | grep -q "tos 0xb8"'
check TC-dscp-rtp-ef         eval 'capture teN1 n1 "udp port 12000" 2 udp 10.2.0.2 12000 | grep -q "tos 0xb8"'
check TC-dscp-video-af41     eval 'capture teN1 n1 "udp port 3480" 2 udp 10.2.0.2 3480 | grep -q "tos 0x88"'
check TC-dscp-bulk-cs1       eval 'capture teN1 n1 "tcp port 873" 2 syn 10.2.0.2 873 | grep -q "tos 0x20"'
check TC-dscp-other-unchanged eval 'capture teN1 n1 "udp port 53" 2 udp 10.2.0.2 53 | grep -q "tos 0x0,"'
check TC-dscp-checksums      eval '! capture teN1 n1 "udp port 5060" 2 udp 10.2.0.2 5060 | grep -q "bad\|incorrect"'
$H1 "$BPFC" -i h1 -c

echo "sampled-mirror.bpfc: 1 in 10 packets to mon0"
$R "$BPFC" -i r1 -d ingress -p 10 -s RATE=10 -f "$EX/sampled-mirror.bpfc" >/dev/null || test_fail "mirror attach"
burst() { $H1 python3 -c '
import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(2000): s.sendto(b"m" * 64, ("10.2.0.2", 7777))'; }
ip netns exec teM timeout 4 tcpdump -nn -i m0 "udp port 7777" > "$T/mir" 2>"$T/mir.err" & mp=$!
for _ in $(seq 50); do grep -q "listening on" "$T/mir.err" 2>/dev/null && break; sleep 0.1; done
sleep 0.2
delivered=$(count teN1 n1 "udp port 7777" 3 burst); wait $mp
mirrored=$(grep -c . "$T/mir")
check TC-mirror-sample-rate  eval '[ $mirrored -ge 120 ] && [ $mirrored -le 300 ]'
check TC-mirror-traffic-intact eval '[ $delivered -eq 2000 ]'
$R "$BPFC" -i r1 -c

echo "policer.bpfc: 10.1.0.0/24 policed to 8 Mbit/s"
$R "$BPFC" -i r1 -d ingress -p 10 -m "$T/m" -f "$EX/policer.bpfc" >/dev/null || test_fail "policer attach"
flood() { $H1 python3 -c '
import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); n = 0; t = time.time()
while time.time() - t < 2: s.sendto(b"p" * 1400, ("10.2.0.2", 7778)); n += 1
print(n)'; }
b0=$(rxb teN1 n1); sent=$(flood); sleep 0.3; got=$(( $(rxb teN1 n1) - b0 ))
# 2 s at 1 MB/s plus the 30 kB burst; the sender offers far more
check TC-policer-offered-more eval '[ $(( sent * 1442 )) -gt 6000000 ]'

check TC-policer-rate        eval '[ $got -ge 1500000 ] && [ $got -le 2700000 ]'
$R "$BPFC" -i r1 -c

echo "host-accounting.bpfc: both hooks of r2"
for h in ingress egress; do $R "$BPFC" -i r2 -d $h -p 10 -m "$T/m" -f "$EX/host-accounting.bpfc" >/dev/null || test_fail "accounting $h attach"; done
$H1 ping -q -c 5 -s 1000 -W1 10.2.0.2 >/dev/null
acct() { local v; v=$("$BPFC" -m "$T/m" -r BYTES_$1 | awk '$3 == "0x000000000a010002" {print $6}'); echo $(( ${v:-0} )); }
check TC-accounting-egress   eval '[ $(acct egress) -eq $(( 5 * 1042 )) ]'
check TC-accounting-ingress  eval '[ $(acct ingress) -eq $(( 5 * 1042 )) ]'
$R "$BPFC" -i r2 -c

echo "edt-pacing.bpfc: 10.2.0.0/24 paced to 16 Mbit/s (needs the fq qdisc)"
if $R tc qdisc replace dev r2 root fq 2>/dev/null; then
	head -c 2000000 /dev/urandom > "$T/src"
	xfer() { # seconds for 2 MB over TCP from H1 to N1
		$N1 timeout 10 python3 -c '
import socket, sys
l = socket.create_server(("10.2.0.2", 7002)); c, _ = l.accept()
with open(sys.argv[1], "wb") as f:
    while (d := c.recv(65536)): f.write(d)' "$T/dst" & local l=$!; sleep 0.5
		local t0; t0=$(date +%s.%N)
		$H1 timeout 9 python3 -c '
import socket, sys
s = socket.create_connection(("10.2.0.2", 7002)); s.sendall(open(sys.argv[1], "rb").read()); s.close()' "$T/src"; wait $l
		echo "$(date +%s.%N) - $t0" | bc
	}
	fast=$(xfer)
	$R "$BPFC" -i r2 -d egress -p 10 -m "$T/m" -s NET=10.2.0.0/24 -f "$EX/edt-pacing.bpfc" >/dev/null || test_fail "pacing attach"
	paced=$(xfer)
	check TC-pacing-intact     cmp -s "$T/src" "$T/dst"
	# 2 MB at 2 MB/s: about a second; unpaced it is a few ms
	check TC-pacing-rate       eval '[ $(echo "$paced > 0.8 && $paced < 3" | bc) = 1 ] && [ $(echo "$fast < 0.5" | bc) = 1 ]'
	$R "$BPFC" -i r2 -c; $R tc qdisc del dev r2 root 2>/dev/null
else
	test_skip "TC-pacing (no fq qdisc: sch_fq)"
fi

tests_exit
