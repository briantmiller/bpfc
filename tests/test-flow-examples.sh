#!/bin/bash
#
# The flow-tracking examples in dist/examples/flow (doc/flow-tracking.md),
# run as they are, with packets built by tests/keys-send.py. (The NAT
# examples are tested in tests/test-nat.sh.)
#
#   FA fa0 10.66.0.1 ---- fr0 10.66.0.2  FR  fw0 ---- x0
#                                            fw1 ---- x1  FX
#                                            fw2 ---- x2

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root flow-examples
require_cmds flow-examples python3 ip tc

BPFC=$PWD/bpfc
EX=$PWD/dist/examples/flow
DOC=$PWD/doc/flow-tracking.md
SEND=$PWD/tests/keys-send.py
MAPS=/run/bpfc-flowex-$$
cleanup() {
	for n in FA FR FX; do ip netns del $n 2>/dev/null; done
	umount $MAPS 2>/dev/null; rmdir $MAPS 2>/dev/null
}
trap 'cleanup; rm -f "$TESTS_FAILED_FILE"' EXIT
cleanup
mkdir -p $MAPS && mount -t bpf bpffs $MAPS || { test_fail "mount bpffs"; exit 1; }

echo "== the guide shows every example file as it is"
for f in $EX/*.bpfc; do
	check "in-guide-$(basename $f .bpfc)" python3 -c '
import sys; sys.exit(open(sys.argv[1]).read().rstrip("\n") not in open(sys.argv[2]).read())' "$f" "$DOC"
done

echo "== every example loads (verifier), on each hook it is meant for"
for f in $EX/*.bpfc; do
	n=$(basename $f .bpfc)
	for h in ingress egress xdp; do
		case $n:$h in flow-sample:xdp) continue ;; esac          # clone is TC only
		if $BPFC -m $MAPS -T -d $h -s COLLECTOR=lo -f $f >/dev/null 2>&1; then test_pass "load-$n-$h"
		else test_fail "load-$n-$h"; $BPFC -m $MAPS -T -d $h -s COLLECTOR=lo -f $f 2>&1 | tail -2; fi
	done
done

for n in FA FR FX; do ip netns add $n; ip -n $n link set lo up; done
ip link add fa0 netns FA type veth peer name fr0 netns FR
for i in 0 1 2; do ip link add fw$i netns FR type veth peer name x$i netns FX; ip -n FR link set fw$i up; ip -n FX link set x$i up; done
ip -n FA link set fa0 up; ip -n FR link set fr0 up
ip -n FA addr add 10.66.0.1/24 dev fa0; ip -n FR addr add 10.66.0.2/24 dev fr0
RMAC=$(ip -n FR -o link show fr0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')
R() { ip netns exec FR "$@"; }
X() { ip netns exec FX "$@"; }
send() { ip netns exec FA python3 -I $SEND fa0 $RMAC "$@"; sleep 0.3; }
bp() { $BPFC -m $MAPS "$@"; }
attach() { R $BPFC -m $MAPS -i fr0 -d ingress -p 10 "$@" >/dev/null || test_fail "attach $*"; }
# counts what passed the example (priority 200 runs only if the example did not drop)
passed() { R $BPFC -m $MAPS -i fr0 -d ingress -p 200 "count PASS $*" >/dev/null || test_fail "attach counter"; }
reset() { R $BPFC -i fr0 -c; rm -f $MAPS/[A-Z]*; }
# dv MAP: the first entry's value, in decimal
dv() { local x; x=$(bp -r $1 | awk '/Key:/ {print $6; exit}'); echo $(( ${x:-0} )); }

echo "== fw-loadshare: both directions of each flow leave through the same link"
attach -f $EX/fw-loadshare.bpfc
for i in 0 1 2; do bp -w FW_LINKS $i $(R cat /sys/class/net/fw$i/ifindex) >/dev/null; done
for i in 0 1 2; do X $BPFC -m $MAPS -i x$i -d ingress -p 10 'count ARR_$IFNAME symmetric ip-src ip-dst ip-proto src-port dst-port' >/dev/null; done
specs=()
for i in $(seq 1 30); do
	specs+=(proto=tcp,src=10.66.0.1,dst=10.77.0.9,sport=$((2000 + i)),dport=80)
	specs+=(proto=tcp,src=10.77.0.9,dst=10.66.0.1,sport=80,dport=$((2000 + i)))
done
send "${specs[@]}"
J=$(bp -R ARR_x0,ARR_x1,ARR_x2 | tail -n +2)
one_link() { echo "$J" | awk 'NF != 4 { bad = 1 } { n = 0; for (i = 2; i <= 4; i++) if ($i == "0x2") n++; else if ($i != "-") bad = 1; if (n != 1) bad = 1 } END { exit bad || NR != 30 }'; }
check "30 flows, each seen on exactly one link, both directions there" one_link
for i in 0 1 2; do
	c=$(echo "$J" | awk -v c=$((i + 2)) '$c != "-"' | wc -l)
	check "link fw$i carries some flows ($c)" [ $c -ge 3 ]
done
for i in 0 1 2; do X $BPFC -i x$i -c; done
reset

echo "== copp: BGP only from peers, SSH limited per source, transit untouched"
attach -f $EX/copp.bpfc
passed ip-src dst-port
bp -w LOCAL 10.66.0.2/32 1 >/dev/null; bp -w BGP_PEERS 10.66.0.1/32 1 >/dev/null
send proto=tcp,src=10.66.0.1,dst=10.66.0.2,sport=40000,dport=179,count=3 \
     proto=tcp,src=10.66.0.5,dst=10.66.0.2,sport=40000,dport=179,count=3 \
     proto=tcp,src=10.66.0.7,dst=10.66.0.2,dport=22,tcpflags=2,count=50 \
     proto=tcp,src=10.66.0.7,dst=10.99.0.1,dport=22,tcpflags=2,count=30
T=$(bp -r PASS -K 'ip-src dst-port')
pc() { echo "$T" | awk -v s=$1 -v p=$2 '$1 == s && $2 == p {print $3}'; }
check "BGP from the peer passes ($(pc 10.66.0.1 179))" [ "$(pc 10.66.0.1 179)" = 3 ]
check "BGP from elsewhere is dropped ($(pc 10.66.0.5 179))" [ -z "$(pc 10.66.0.5 179)" ]
reset
attach -f $EX/copp.bpfc
R $BPFC -m $MAPS -i fr0 -d ingress -p 200 'match ip-dst 10.66.0.2; count PASSL dst-port; end-match; match ip-dst 10.99.0.1; count PASST dst-port; end-match' >/dev/null
bp -w LOCAL 10.66.0.2/32 1 >/dev/null
send proto=tcp,src=10.66.0.7,dst=10.66.0.2,dport=22,tcpflags=2,count=50 proto=tcp,src=10.66.0.7,dst=10.99.0.1,dport=22,tcpflags=2,count=30
L=$(bp -r PASSL -K dst-port | awk '$1 == 22 {print $2}'); TR=$(bp -r PASST -K dst-port | awk '$1 == 22 {print $2}')
check "SSH to the router: a burst of 50 passes 20-21 (${L:-0})" [ "${L:-0}" -ge 20 -a "${L:-0}" -le 21 ]
check "SSH in transit is not policed (${TR:-0} of 30)" [ "${TR:-0}" = 30 ]
reset

echo "== storm-control: ARP per source MAC"
attach -f $EX/storm-control.bpfc
passed src-mac:8
send l3=arp,count=100
A=$(dv PASS)
check "ARP burst of 100: 40-41 pass (${A:-0})" [ "${A:-0}" -ge 40 -a "${A:-0}" -le 41 ]
reset

echo "== customer-accounting and conversations: readable keys"
attach -f $EX/customer-accounting.bpfc
send proto=udp,vlan=101,src=100.64.1.20,count=4 proto=udp,vlan=102,src=100.64.7.3,count=2
check "customer-accounting: -K 'vlan-id ip-src'" sh -c "$BPFC -m $MAPS -r CUST_P -K 'vlan-id ip-src' | grep -qx '101 100.64.1.20 4' && $BPFC -m $MAPS -r CUST_P -K 'vlan-id ip-src' | grep -qx '102 100.64.7.3 2'"
reset
attach -f $EX/conversations.bpfc
send proto=udp,src=10.66.0.1,dst=10.77.0.9,count=3 proto=udp,src=10.77.0.9,dst=10.66.0.1,count=2
check "conversations: both directions in one entry, lower address first" sh -c "$BPFC -m $MAPS -r CONV_P -K 'ip-src ip-dst' | grep -qx '10.66.0.1 10.77.0.9 5'"
reset

echo "== flow-sample: whole flows, one in N, both directions"
R $BPFC -m $MAPS -i fr0 -d ingress -p 10 -s N=4 -s COLLECTOR=fw0 -f $EX/flow-sample.bpfc >/dev/null || test_fail "attach flow-sample"
X $BPFC -m $MAPS -i x0 -d ingress -p 10 'count MIRR 0' >/dev/null
specs=(); want=0
for i in $(seq 1 40); do
	specs+=(proto=udp,src=10.66.0.1,dst=10.77.0.9,sport=$((3000 + i)),dport=53)
	specs+=(proto=udp,src=10.77.0.9,dst=10.66.0.1,sport=53,dport=$((3000 + i)))
	[ $(( $($BPFC -H "hash buckets 4 symmetric ip-src=10.66.0.1 ip-dst=10.77.0.9 ip-proto=17 src-port=$((3000 + i)) dst-port=53") )) -eq 0 ] && { want=$((want + 1)); last=$i; }
done
send "${specs[@]}"
got=$(bp -r SAMPLE_P | grep -c 'Value: 0x0000000000000002')
check "flows sampled = those bpfc -H puts in bucket 0 ($got of 40, expected $want), 2 packets each" [ $got -eq $want -a $want -gt 0 ]
K=$($BPFC -H "hash 64 symmetric ip-src=10.66.0.1 ip-dst=10.77.0.9 ip-proto=17 src-port=$((3000 + last)) dst-port=53")
check "a sampled flow's entry is found with bpfc -H" sh -c "$BPFC -m $MAPS -r SAMPLE_P | grep -q 'Key: $K -> Value: 0x0000000000000002'"
M=$(dv MIRR)
check "the sampled packets were copied to the collector (${M:-0} of $((2 * want)))" [ "${M:-0}" -eq $((2 * want)) ]
X $BPFC -i x0 -c
reset

echo "== dedup-simple: the second copy is dropped"
attach -f $EX/dedup-simple.bpfc
passed ip-ident
send proto=udp,ident=100,count=2 proto=udp,ident=101,count=2 proto=udp,ident=102
check "three packets, each passed once" sh -c "[ \"\$($BPFC -m $MAPS -r PASS -K ip-ident | tail -n +2 | sort)\" = \"\$(printf '100 1\n101 1\n102 1')\" ]"
reset

echo "== tenant-marker: AF11 within the rate, AF13 above"
attach -s CIR=1mbit -f $EX/tenant-marker.bpfc
passed dscp
send proto=udp,src=10.20.1.1,len=958,count=400
T=$(bp -r PASS -K dscp)
G=$(echo "$T" | awk '$1 == "af11" {print $2}'); Y=$(echo "$T" | awk '$1 == "af13" {print $2}')
check "256 KiB burst at 1 Mbit/s: 250-300 x AF11 (${G:-0}), the rest AF13 (${Y:-0})" [ "${G:-0}" -ge 250 -a "${G:-0}" -le 300 -a $(( ${G:-0} + ${Y:-0} )) -eq 400 ]
reset

echo "== policer-rate and syn-guard-subnet"
attach -s NET=10.66.0.0/24 -s RATE=1mbit -s BURST=10000 -f $EX/policer-rate.bpfc
passed 0:8
send proto=udp,src=10.66.0.1,len=958,count=100
P=$(dv PASS)
check "policer: 100 x 1000 bytes, 10 KB burst: about 10 pass (${P:-0})" [ "${P:-0}" -ge 9 -a "${P:-0}" -le 16 ]
reset
attach -s LIMIT=10/s -f $EX/syn-guard-subnet.bpfc
passed ip-src
send proto=tcp,tcpflags=2,src=10.5.5.1,count=2010 proto=tcp,tcpflags=2,src=10.5.5.2,count=20 proto=tcp,tcpflags=2,src=10.5.6.1,count=20
T=$(bp -r PASS -K ip-src)
a=$(echo "$T" | awk '$1 == "10.5.5.1" {print $2}'); b=$(echo "$T" | awk '$1 == "10.5.5.2" {print $2}'); c=$(echo "$T" | awk '$1 == "10.5.6.1" {print $2}')
check "SYNs per /24: the burst of 2000 is shared by 10.5.5.0/24 (${a:-0} + ${b:-0}), another /24 is not affected (${c:-0})" [ $(( ${a:-0} + ${b:-0} )) -ge 2000 -a $(( ${a:-0} + ${b:-0} )) -le 2004 -a "${c:-0}" = 20 ]
reset

tests_exit
