#!/bin/bash
#
# portscan-guard (programs/portscan-guard) with bpfc-portscanctl: per-address
# and per-prefix tracking, blocking, and the control commands, with packets
# built by tests/keys-send.py.
#
#   PA pa0 10.66.0.1 ---- pr0 10.66.0.2  PR (guard on pr0 ingress)

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root portscan
require_cmds portscan python3 ip tc

BPFC=$PWD/bpfc
PROG=$PWD/programs/portscan-guard/examples/interfaces.d/eth0/ingress/10.bpfc
EGRESS=$PWD/programs/portscan-guard/examples/interfaces.d/eth0/egress/10.bpfc
CTL_BIN=$PWD/programs/portscan-guard/bpfc-portscanctl
SEND=$PWD/tests/keys-send.py
MAPS=/run/bpfc-portscan-$$
cleanup() {
	for n in PA PR; do ip netns del $n 2>/dev/null; done
	umount $MAPS 2>/dev/null; rmdir $MAPS 2>/dev/null
}
trap 'cleanup; rm -f "$TESTS_FAILED_FILE"' EXIT
cleanup
mkdir -p $MAPS && mount -t bpf bpffs $MAPS || { test_fail "mount bpffs"; exit 1; }

echo "== loads (verifier) on each hook"
for h in ingress egress xdp; do
	if $BPFC -m $MAPS -T -d $h -f $PROG >/dev/null 2>&1; then test_pass "load-$h"
	else test_fail "load-$h"; $BPFC -m $MAPS -T -d $h -f $PROG 2>&1 | tail -2; fi
done
check "load-egress-companion" eval "$BPFC -m $MAPS -T -d egress -f $EGRESS >/dev/null"

for n in PA PR; do ip netns add $n; ip -n $n link set lo up; done
ip link add pa0 netns PA type veth peer name pr0 netns PR
ip -n PA link set pa0 up; ip -n PR link set pr0 up
ip -n PA addr add 10.66.0.1/24 dev pa0; ip -n PR addr add 10.66.0.2/24 dev pr0
RMAC=$(ip -n PR -o link show pr0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')
R() { ip netns exec PR "$@"; }
send() { ip netns exec PA python3 -I $SEND pa0 $RMAC "$@"; sleep 0.3; }
CTL() { R "$CTL_BIN" --bpfc $BPFC --map-dir $MAPS "$@"; }
# the guard at 10; priority 200 counts what it let through, per source address
attach() {
	R $BPFC -m $MAPS -i pr0 -d ingress -p 10 -f "${1:-$PROG}" >/dev/null || test_fail "attach guard"
	R $BPFC -m $MAPS -i pr0 -d ingress -p 200 "match ip; count PASS ip-src; end-match" >/dev/null || test_fail "attach counter"
}
reset() { R $BPFC -i pr0 -c; R $BPFC -i pr0 -d egress -c; rm -f $MAPS/[A-Z]*; }
AMAC=$(ip -n PA -o link show pa0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')
# out SPEC...: frames leaving pr0 (through its TC egress) towards PA
out() { R python3 -I $SEND pr0 $AMAC "$@"; sleep 0.3; }
stat() { CTL stats | awk -v t="$1" 'index($0, t) { print $NF }'; }
# passed ADDR: packets from ADDR that got past the guard
passed() {
	local k v
	k=$(printf '0x%016x' $(( $(echo "$1" | awk -F. '{print ($1*16777216)+($2*65536)+($3*256)+$4}') )))
	v=$($BPFC -m $MAPS -r PASS | awk -v k="$k" '$3 == k {print $6}')
	echo $(( ${v:-0} ))
}
# scan NET N PORT0: N SYNs, from NET.1 .. NET.N, each to its own port
scan() {
	local specs=() i
	for i in $(seq 1 $2); do specs+=(proto=tcp,tcpflags=2,src=$1.$i,dst=10.66.0.2,sport=33000,dport=$(( $3 + i ))); done
	send "${specs[@]}"
}
# has CMD REGEX / hasnt CMD REGEX: bpfc-portscanctl CMD output matches (or not)
has() { local c=$1; shift; CTL $c | grep -qE "$@"; }
hasnt() { ! has "$@"; }
fails() { ! CTL "$@" >/dev/null 2>&1; }
syn() { send proto=tcp,tcpflags=2,src=$1,dst=10.66.0.2,sport=33001,dport=${2:-80}; }

attach

echo "== defaults: monitor mode, /32"
check "config: prefix /32" has config 'source prefix length \(1\.\.32\) = /32'
check "config: mode monitor" has config '= monitor'
specs=()
for p in $(seq 40001 40014); do specs+=(proto=tcp,tcpflags=2,src=10.77.9.9,dst=10.66.0.2,sport=33000,dport=$p); done
send "${specs[@]}"
syn 10.77.9.9
check "monitor: a host over the threshold is SUSPECT" has status '^10\.77\.9\.9 +SUSPECT'
check "monitor: nothing dropped (15 of 15 passed)" [ "$(passed 10.77.9.9)" -eq 15 ]

echo "== /32: a scan spread over 20 addresses of one /24 is not detected"
scan 10.77.1 20 41000
check "no SUSPECT or BLOCKED 10.77.1.x" hasnt status '^10\.77\.1\.[0-9]+ +(SUSPECT|BLOCKED)'
check "each address tracked with score 1" [ "$(CTL status | grep -cE '^10\.77\.1\.[0-9]+ +TRACKING +1 ')" -eq 20 ]

echo "== set prefix and mode"
CTL set prefix 24 >/dev/null
CTL set mode block >/dev/null
check "config: prefix /24" has config '= /24'
check "set prefix 0 refused" fails set prefix 0
check "set prefix 33 refused" fails set prefix 33
check "set prefix /16 accepted" eval 'CTL set prefix /16 >/dev/null && has config "= /16" && CTL set prefix 24 >/dev/null'

echo "== /24: the same spread scan is added up and blocks the whole /24"
scan 10.77.2 20 42000
CTL status > /tmp/ps-status.$$
check "10.77.2.0/24 BLOCKED" grep -qE '^10\.77\.2\.0/24 +BLOCKED' /tmp/ps-status.$$
check "status shows the last host of the /24" grep -qE '^10\.77\.2\.0/24 +BLOCKED +[0-9]+ +[0-9]+ +10\.77\.2\.[0-9]+ +TCP/' /tmp/ps-status.$$
check "status header names the prefix" grep -q 'tracked per /24' /tmp/ps-status.$$
rm -f /tmp/ps-status.$$
n=0; for i in $(seq 1 20); do n=$(( n + $(passed 10.77.2.$i) )); done
check "the first 11 contacts passed, the rest dropped ($n passed)" [ $n -eq 11 ]
syn 10.77.2.200
check "another host of the blocked /24 is dropped" [ "$(passed 10.77.2.200)" -eq 0 ]
syn 10.77.3.1
check "a host of the next /24 passes" [ "$(passed 10.77.3.1)" -eq 1 ]
check "flows lists the /24" has flows '^10\.77\.2\.0/24 +TCP +420'

echo "== /24: many hosts reaching one port (NAT pool) count that port once"
specs=()
for i in $(seq 1 40); do specs+=(proto=tcp,tcpflags=2,src=10.77.5.$i,dst=10.66.0.2,sport=33000,dport=443); done
send "${specs[@]}"
check "10.77.5.0/24 TRACKING with score 1" has status '^10\.77\.5\.0/24 +TRACKING +1 '
n=0; for i in $(seq 1 40); do n=$(( n + $(passed 10.77.5.$i) )); done
check "all 40 passed ($n)" [ $n -eq 40 ]

echo "== unblock, manual blocks, clear"
check "unblock 10.77.2.0/24" eval 'CTL unblock 10.77.2.0/24 | grep -q "for 10.77.2.0/24"'
syn 10.77.2.201 42001   # a port the /24 already reached: not a new contact
check "the /24 passes after unblock" [ "$(passed 10.77.2.201)" -eq 1 ]
CTL block 10.77.4.5 >/dev/null
syn 10.77.4.5; syn 10.77.4.6
check "manual /32 block under /24: that host dropped" [ "$(passed 10.77.4.5)" -eq 0 ]
check "manual /32 block under /24: its neighbour passes" [ "$(passed 10.77.4.6)" -eq 1 ]
check "block 10.77.0.0/16 refused under /24" fails block 10.77.0.0/16
check "block normalises host bits" eval 'CTL block 10.77.6.99/24 60 | grep -q "Blocked 10.77.6.0/24 for 60"'
syn 10.77.6.1
check "manual /24 block drops" [ "$(passed 10.77.6.1)" -eq 0 ]
check "unblock ADDR clears its /32 and its /24" eval 'CTL unblock 10.77.6.1 | grep -q "10.77.6.1 10.77.6.0/24"'
syn 10.77.6.2
check "the /24 passes after unblock ADDR" [ "$(passed 10.77.6.2)" -eq 1 ]
scan 10.77.7 20 43000
check "10.77.7.0/24 blocked again" has status '^10\.77\.7\.0/24 +BLOCKED'
check "clear 10.77.7.0/24" eval 'CTL clear 10.77.7.0/24 | grep -qE "Cleared 10.77.7.0/24: .* 1 score bucket.* 12 flow tuple"'
check "cleared /24 gone from status and flows" eval 'hasnt status "^10\.77\.7\." && hasnt flows "^10\.77\.7\."'

echo "== changing the prefix: blocks of another length are INACTIVE"
scan 10.77.8 20 44000
CTL set prefix 16 >/dev/null
check "the /24 block is listed INACTIVE under /16" has status '^10\.77\.8\.0/24 +INACTIVE'
syn 10.77.8.50
check "and no longer enforced" [ "$(passed 10.77.8.50)" -eq 1 ]
syn 10.77.4.5
check "manual /32 block still enforced under /16" [ "$(passed 10.77.4.5)" -eq 0 ]

echo "== /32 again: per-address behaviour as before"
reset; attach
CTL set mode block >/dev/null
specs=()
for p in $(seq 45001 45012); do specs+=(proto=tcp,tcpflags=2,src=10.77.10.1,dst=10.66.0.2,sport=33000,dport=$p); done
send "${specs[@]}"; syn 10.77.10.1; syn 10.77.10.2
check "the scanning address is BLOCKED (bare address in status)" has status '^10\.77\.10\.1 +BLOCKED'
check "11 of its 13 packets passed" [ "$(passed 10.77.10.1)" -eq 11 ]
check "its neighbour passes" [ "$(passed 10.77.10.2)" -eq 1 ]
send proto=udp,src=10.77.10.3,dst=10.66.0.2,dport=53
check "UDP from another address passes" [ "$(passed 10.77.10.3)" -eq 1 ]

echo "== UDP: without the egress program, DNS answers look like a scan"
reset; attach
CTL set mode block >/dev/null
specs=()
for i in $(seq 1 15); do specs+=(proto=udp,src=10.77.53.53,dst=10.66.0.2,sport=53,dport=$((33000 + i * 7))); done
send "${specs[@]}"
check "the resolver is BLOCKED" has status '^10\.77\.53\.53 +BLOCKED'

echo "== UDP: with the egress program, answers to our queries are trusted"
reset; attach
R $BPFC -m $MAPS -i pr0 -d egress -p 10 -f $EGRESS >/dev/null || test_fail "attach egress"
CTL set mode block >/dev/null
q=(); a=()
for i in $(seq 1 15); do
	q+=(proto=udp,src=10.66.0.2,dst=10.77.53.53,sport=$((33000 + i * 7)),dport=53)
	a+=(proto=udp,src=10.77.53.53,dst=10.66.0.2,sport=53,dport=$((33000 + i * 7)))
done
out "${q[@]}"
check "udp lists 15 trusted flows" [ "$(CTL udp | grep -c '^10\.77\.53\.53 .* trusted')" -eq 15 ]
send "${a[@]}"
check "all 15 answers passed" [ "$(passed 10.77.53.53)" -eq 15 ]
check "the resolver is not tracked" hasnt status '^10\.77\.53\.53 '
check "stats: 15 trusted UDP replies" [ "$(stat 'trusted UDP replies')" -eq 15 ]
check "stats: no untrusted UDP" [ "$(stat 'UDP packets observed')" -eq 0 ]

echo "== UDP: what is not an answer is still scored"
specs=()
for i in $(seq 1 15); do specs+=(proto=udp,src=10.77.54.54,dst=10.66.0.2,sport=53,dport=$((40000 + i))); done
send "${specs[@]}"
check "port 53 answers nobody asked for: BLOCKED" has status '^10\.77\.54\.54 +BLOCKED'
check "11 of them passed" [ "$(passed 10.77.54.54)" -eq 11 ]
u=$(stat 'UDP packets observed')
send proto=udp,src=10.77.53.53,dst=10.66.0.2,sport=54,dport=33007
check "a queried resolver from another port is untrusted" [ "$(stat 'UDP packets observed')" -eq $((u + 1)) ]
send proto=udp,src=10.77.53.99,dst=10.66.0.2,sport=53,dport=33007
check "another address to a queried port is untrusted" [ "$(stat 'UDP packets observed')" -eq $((u + 2)) ]

echo "== UDP: an answer passes while its source is blocked"
out proto=udp,src=10.66.0.2,dst=10.77.54.54,sport=45000,dport=53
send proto=udp,src=10.77.54.54,dst=10.66.0.2,sport=53,dport=45000
check "answer from the blocked resolver passed" [ "$(passed 10.77.54.54)" -eq 12 ]
send proto=udp,src=10.77.54.54,dst=10.66.0.2,sport=53,dport=45001
check "other packets from it are still dropped" [ "$(passed 10.77.54.54)" -eq 12 ]
check "and the block stays" has status '^10\.77\.54\.54 +BLOCKED'

echo "== UDP: the trust expires"
check "set udp-timeout 1" eval 'CTL set udp-timeout 1 >/dev/null && has config "UDP reply trust timeout \(seconds\) = 1$"'
check "set udp-timeout 0 refused" fails set udp-timeout 0
out proto=udp,src=10.66.0.2,dst=10.77.55.55,sport=46000,dport=123
sleep 2.2
before=$(stat 'trusted UDP replies')
send proto=udp,src=10.77.55.55,dst=10.66.0.2,sport=123,dport=46000
check "an answer after the timeout is not trusted" [ "$(stat 'trusted UDP replies')" -eq "$before" ]
check "and is tracked as a contact" has status '^10\.77\.55\.55 +TRACKING'
check "udp --all lists it expired" eval 'CTL udp --all | grep -qE "^10\.77\.55\.55 +123 +46000 .* expired"'

R $BPFC -i pr0 -d egress -c
R $BPFC -i pr0 -c
tests_exit
