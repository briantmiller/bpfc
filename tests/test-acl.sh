#!/bin/bash
#
# The IOS access-list frontend (frontends/acl): every kind of entry is sent
# packets that should and should not match it, and the entry's own counter
# (BPFC_ACL_P, under the key its meta line names) must show exactly the
# packets it matched: first match wins, implicit deny last.
#
#   tests/test-acl.sh          (root; needs python3 for the packet sender)

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root acl
require_cmds acl python3 ip tc

BPFC=$PWD/bpfc
SEND=$PWD/tests/keys-send.py
MAPS=/run/bpfc-acl-$$
WORK=$(mktemp -d /tmp/bpfc-acl.XXXXXX)
FE=$WORK/fe
CONF=$WORK/conf

cleanup() {
	[ -n "$DPID" ] && kill $DPID 2>/dev/null
	ip netns del AA 2>/dev/null
	ip netns del AB 2>/dev/null
	umount $MAPS 2>/dev/null
	rmdir $MAPS 2>/dev/null
}
trap 'cleanup; rm -rf "$WORK" "$TESTS_FAILED_FILE"' EXIT
cleanup
# the frontend runs unprivileged (nobody or bpfc): it must reach its files
chmod 755 $WORK
mkdir -p $MAPS $FE $CONF/acl.d && mount -t bpf bpffs $MAPS || { test_fail "mount bpffs on $MAPS"; exit 1; }
if [ -x frontends/acl ]; then cp frontends/acl $FE/acl
else ${CC:-cc} -O2 -Wall -o $FE/acl frontends/acl.c || { test_fail "build frontends/acl"; exit 1; }; fi
export BPFC_FRONTEND_DIRS=$FE

ip netns add AA
ip netns add AB
ip link add aa0 netns AA type veth peer name ab0 netns AB
for n in AA AB; do ip -n $n link set lo up; done
ip -n AA link set aa0 up
ip -n AB link set ab0 up
ip -n AA addr add 10.89.0.1/24 dev aa0
ip -n AB addr add 10.89.0.2/24 dev ab0
AMAC=$(ip -n AA -o link show aa0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')
BMAC=$(ip -n AB -o link show ab0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')

A() { ip netns exec AA "$@"; }
B() { ip netns exec AB "$@"; }
# send <spec...>: frames from AA into ab0 (ab0's ingress)
send() { A python3 -I $SEND aa0 $BMAC "$@"; sleep 0.2; }
# sendb <spec...>: frames out of ab0 (ab0's egress)
sendb() { B python3 -I $SEND ab0 $AMAC "$@"; sleep 0.2; }

# load <dir> <prio> <file>: compiles and attaches an ACL file on ab0; its
# meta lines (one per entry, with the counter key) go to $WORK/meta
load() {
	local out
	out=$(B env BPFC_CONF_ROOT=$CONF $BPFC -m $MAPS -i ab0 -d $1 -p $2 -I -f $3 2>&1)
	local rc=$?
	echo "$out" | sed -n 's/^BPFC_META //p' >> $WORK/meta
	[ $rc -eq 0 ] || { echo "$out" | tail -5; return 1; }
}
unload() { B $BPFC -i ab0 -d $1 -p $2 -D >/dev/null 2>&1; }
# hits <acl> <seq|implicit>: packets counted for the entry so far
hits() {
	local key
	key=$(awk -v a=$1 -v s=$2 '$1 == "acl-rule" && $2 == a && $3 == s { k = $4 } END { print k }' $WORK/meta)
	[ -n "$key" ] || { echo "no-entry"; return; }
	local v
	v=$($BPFC -m $MAPS -r BPFC_ACL_P | awk -v k=0x$key '$3 == k { v = $6 } END { print v }')
	echo $((${v:-0}))
}
# expect <name> <acl> <seq> <n>
expect() { local got; got=$(hits $2 $3); check "$1 ($2 $3: $got, want $4)" [ "$got" = "$4" ]; }
reject() { local name=$1; shift; if B env BPFC_CONF_ROOT=$CONF $BPFC -m $MAPS -i ab0 -T "$@" >$WORK/err 2>&1; then test_fail "$name (accepted)"; else test_pass "$name: $(grep -v "^Error: frontend" $WORK/err | tail -1)"; fi; }

echo "== extended IPv4 list"
cat > $WORK/20.acl <<'EOF'
ip access-list extended EDGE-IN
 remark web servers
 10 permit tcp any host 10.0.0.1 eq www 443
 20 permit udp 10.1.0.0 0.0.255.255 any range 1000 2000 log
 30 deny icmp any any echo
 40 permit tcp any any established
 50 permit ip 10.2.0.0 0.0.0.255 any fragments
 60 permit ip any any dscp ef
 70 permit ip 10.3.0.1 0.0.255.0 any
 80 permit tcp any any eq 22 syn
 90 deny udp any any eq 53
 100 permit udp any any eq domain 123
EOF
load ingress 20 $WORK/20.acl || test_fail "load EDGE-IN"
send proto=tcp,src=10.9.0.1,dst=10.0.0.1,dport=80,tcpflags=2
send proto=tcp,src=10.9.0.1,dst=10.0.0.1,dport=443,tcpflags=2
send proto=tcp,src=10.9.0.1,dst=10.0.0.2,dport=443,tcpflags=2
expect "eq www 443"          EDGE-IN 10 2
send proto=udp,src=10.1.7.7,dst=10.0.0.9,dport=1500
send proto=udp,src=10.1.7.7,dst=10.0.0.9,dport=2000
send proto=udp,src=10.1.7.7,dst=10.0.0.9,dport=2001
expect "range 1000 2000"     EDGE-IN 20 2
send proto=icmp,src=10.9.0.1,dst=10.0.0.9,icmptype=8
send proto=icmp,src=10.9.0.1,dst=10.0.0.9,icmptype=0
expect "deny icmp echo"      EDGE-IN 30 1
send proto=tcp,src=10.9.0.1,dst=10.0.0.9,dport=5555,tcpflags=16
send proto=tcp,src=10.9.0.1,dst=10.0.0.9,dport=5555,tcpflags=4
send proto=tcp,src=10.9.0.1,dst=10.0.0.9,dport=5555,tcpflags=1
expect "established"         EDGE-IN 40 2
# later fragments of a TCP packet to 10.0.0.1 match 10 (a permit entry with
# ports matches non-initial fragments on its addresses), not a deny
send proto=tcp,src=10.9.0.1,dst=10.0.0.1,dport=80,frag=off
expect "permit + L4 matches later fragments" EDGE-IN 10 3
send proto=udp,src=10.2.0.5,dst=10.0.0.9,dport=9,frag=off
send proto=udp,src=10.2.0.5,dst=10.0.0.9,dport=9,frag=mf
expect "fragments: later fragments only" EDGE-IN 50 1
send proto=udp,src=10.9.0.1,dst=10.0.0.9,dport=9,tos=184
expect "dscp ef"             EDGE-IN 60 1
send proto=udp,src=10.3.5.1,dst=10.0.0.9,dport=9
send proto=udp,src=10.3.5.2,dst=10.0.0.9,dport=9
expect "non-contiguous wildcard 0.0.255.0" EDGE-IN 70 1
send proto=tcp,src=10.9.0.1,dst=10.0.0.9,dport=22,tcpflags=2
send proto=tcp,src=10.9.0.1,dst=10.0.0.9,dport=22,tcpflags=18
expect "syn (match-all: SYN+ACK counts too)" EDGE-IN 80 1
send proto=udp,src=10.9.0.1,dst=10.0.0.9,dport=53
send proto=udp,src=10.9.0.1,dst=10.0.0.9,dport=123
expect "deny before permit"  EDGE-IN 90 1
expect "eq domain 123"       EDGE-IN 100 1
# not matched above: 10.0.0.2:443, udp 2001, icmp echo-reply, fin-only,
# the first fragment from 10.2.0.5, 10.3.5.2
expect "implicit deny"       EDGE-IN implicit 6
check "log entry seen (BPFC_ACL_LOGSEEN)" [ "$($BPFC -m $MAPS -r BPFC_ACL_LOGSEEN 2>/dev/null | grep -c 0x)" -ge 1 ]
unload ingress 20

echo "== a deny drops, a permit lets through"
cat > $WORK/21.acl <<'EOF'
access-list 110 deny icmp any host 10.89.0.2 echo
access-list 110 permit ip any any
EOF
load ingress 21 $WORK/21.acl || test_fail "load 110"
noping() { ! A ping "$@"; }
check "ping is dropped" noping -c 1 -W 1 10.89.0.2 >/dev/null
expect "numbered extended deny" 110 10 1
cat > $WORK/21.acl <<'EOF'
access-list 110 permit icmp any host 10.89.0.2 echo
access-list 110 permit ip any any
EOF
load ingress 21 $WORK/21.acl || test_fail "reload 110"
check "ping passes" A ping -c 1 -W 1 10.89.0.2 >/dev/null
unload ingress 21

echo "== standard lists, object groups from acl.d"
cat > $CONF/acl.d/objects.acl <<'EOF'
object-group network SERVERS
 description the web farm
 host 10.5.0.1
 10.6.0.0 255.255.255.0
 group-object MORE
object-group network MORE
 10.7.0.0/16
object-group service WEB
 tcp eq 80
 tcp eq 443
 tcp-udp eq 8080
ip access-list standard MGMT
 permit host 10.8.0.1
 permit 10.8.1.0 0.0.0.255
 deny any log
ip access-list extended GROUPS
 10 permit object-group WEB any object-group SERVERS
 20 deny tcp any object-group SERVERS
 30 permit ip any any
EOF
cat > $WORK/22.acl <<'EOF'
interface ab0
 ip access-group GROUPS in
EOF
load ingress 22 $WORK/22.acl || test_fail "load GROUPS"
send proto=tcp,src=10.9.0.1,dst=10.5.0.1,dport=80,tcpflags=2
send proto=tcp,src=10.9.0.1,dst=10.6.0.200,dport=443,tcpflags=2
send proto=udp,src=10.9.0.1,dst=10.7.3.3,dport=8080
send proto=tcp,src=10.9.0.1,dst=10.7.3.3,dport=8080,tcpflags=2
send proto=tcp,src=10.9.0.1,dst=10.5.0.2,dport=80,tcpflags=2
expect "service x network group" GROUPS 10 4
send proto=tcp,src=10.9.0.1,dst=10.6.0.9,dport=22,tcpflags=2
expect "network group, nested" GROUPS 20 1
expect "rest"                GROUPS 30 1
unload ingress 22
echo 'ip access-group MGMT in' > $WORK/23.acl
load ingress 23 $WORK/23.acl || test_fail "load MGMT"
send proto=udp,src=10.8.0.1,dst=10.0.0.9,dport=9
send proto=udp,src=10.8.1.77,dst=10.0.0.9,dport=9
send proto=udp,src=10.8.2.1,dst=10.0.0.9,dport=9
expect "standard host"       MGMT 10 1
expect "standard wildcard"   MGMT 20 1
expect "standard deny any"   MGMT 30 1
unload ingress 23
rm -f $CONF/acl.d/objects.acl

echo "== IPv6"
cat > $WORK/24.acl <<'EOF'
ipv6 access-list V6-IN
 permit tcp any host 2001:db8::1 eq 443
 permit udp 2001:db8:5::/48 any
 deny icmp any any echo-request
 permit ipv6 any any dscp af41 sequence 5
EOF
load ingress 24 $WORK/24.acl || test_fail "load V6-IN"
send l3=6,proto=tcp,src=2001:db8:9::1,dst=2001:db8::1,dport=443,tcpflags=2
send l3=6,proto=tcp,src=2001:db8:9::1,dst=2001:db8::1,dport=443,tcpflags=2,hbh=1
send l3=6,proto=tcp,src=2001:db8:9::1,dst=2001:db8::1,dport=80,tcpflags=2
expect "v6 port, through extension headers" V6-IN 10 2
send l3=6,proto=udp,src=2001:db8:5:1::7,dst=2001:db8::9,dport=9
expect "v6 prefix"           V6-IN 20 1
send l3=6,proto=icmp,src=2001:db8:9::1,dst=2001:db8::9,icmptype=128
expect "v6 icmp echo-request" V6-IN 30 1
send l3=6,proto=udp,src=2001:db8:9::1,dst=2001:db8::9,dport=9,tos=136
expect "sequence 5 comes first, dscp af41" V6-IN 5 1
send l3=6,proto=icmp,src=fe80::1,dst=ff02::1,icmptype=135
send l3=6,proto=icmp,src=fe80::1,dst=ff02::1,icmptype=136
expect "nd-ns/nd-na pass before the implicit deny" V6-IN implicit 1
unload ingress 24

echo "== MAC list"
cat > $WORK/25.acl <<'EOF'
mac access-list extended L2-IN
 deny any any 0x0806 0x0
 permit host 02:00:00:00:00:01 any
 deny any any
EOF
load ingress 25 $WORK/25.acl || test_fail "load L2-IN"
send l3=arp
send proto=udp,src=10.9.0.1,dst=10.0.0.9,dport=9
expect "deny ARP"            L2-IN 10 1
expect "IP is not for a MAC list" L2-IN 30 0
unload ingress 25

echo "== reflexive lists"
cat > $WORK/30.acl <<'EOF'
ip access-list extended OUT
 permit udp any any reflect MIRROR
 permit tcp any any reflect MIRROR timeout 60
 permit ip any any
EOF
cat > $WORK/31.acl <<'EOF'
ip access-list extended IN
 evaluate MIRROR
 deny ip any any
EOF
load egress 30 $WORK/30.acl || test_fail "load OUT"
load ingress 31 $WORK/31.acl || test_fail "load IN"
sendb proto=udp,src=10.89.0.2,dst=10.89.9.9,sport=5000,dport=6000
send proto=udp,src=10.89.9.9,dst=10.89.0.2,sport=6000,dport=5000
send proto=udp,src=10.89.9.9,dst=10.89.0.2,sport=6000,dport=5001
send proto=udp,src=10.89.9.8,dst=10.89.0.2,sport=6000,dport=5000
expect "evaluate: the reply"  IN 10 1
# at least: the kernel of AB may answer something on its own (counted too)
got=$(hits IN 20); check "others denied (IN 20: $got, want 2 or more)" [ "$got" -ge 2 ]
sendb proto=tcp,src=10.89.0.2,dst=10.89.9.9,sport=7000,dport=80,tcpflags=2
send proto=tcp,src=10.89.9.9,dst=10.89.0.2,sport=80,dport=7000,tcpflags=18
expect "tcp reply"            IN 10 2
# a RST ends the entry within 5 s; until then, replies still pass
send proto=tcp,src=10.89.9.9,dst=10.89.0.2,sport=80,dport=7000,tcpflags=4
expect "RST passes"           IN 10 3
unload egress 30
unload ingress 31

echo "== bpfcd: interfaces.d/<if>/ingress/<prio>.acl, show access-lists, log, clear, top"
if [ -x bpfcd/bpfcd ] && [ -x bpfcd/bpfcctl ]; then
	D=$WORK/d
	mkdir -p $D/interfaces.d/ab0/ingress $D/run
	cat > $D/bpfc.conf <<-EOF
	bpfc_path = $BPFC
	config_dir = $D/interfaces.d
	state_dir = $D/run
	map_dir = $MAPS
	EOF
	cat > $D/interfaces.d/ab0/ingress/20.acl <<-'EOF'
	ip access-list extended WEB
	 10 permit tcp any any eq 80 log
	 20 deny udp any any eq 9999 log-input
	 30 permit ip any any
	EOF
	B env BPFC_CONF_ROOT=$CONF $PWD/bpfcd/bpfcd -c $D/bpfc.conf >> $WORK/bpfcd.log 2>&1 &
	DPID=$!
	CTL() { B $PWD/bpfcd/bpfcctl -c $D/bpfc.conf "$@"; }
	for _ in $(seq 100); do grep -q 'status=installed' $D/run/state 2>/dev/null && break; sleep 0.1; done
	check "bpfcd installed 20.acl" grep -q 'iface=ab0 dir=ingress prio=20 .*status=installed' $D/run/state
	send proto=tcp,src=10.9.0.1,dst=10.0.0.9,sport=4321,dport=80,tcpflags=2
	send proto=tcp,src=10.9.0.1,dst=10.0.0.9,sport=4321,dport=80,tcpflags=16
	send proto=udp,src=10.9.0.7,dst=10.0.0.9,sport=53,dport=9999
	send proto=udp,src=10.9.0.7,dst=10.0.0.9,dport=7
	CTL show access-lists > $WORK/show
	check "show access-lists: heading" grep -q '^Extended IP access list WEB$' $WORK/show
	check "show access-lists: 10 ... (2 matches)" grep -q '^    10 permit tcp any any eq 80 log (2 matches)$' $WORK/show
	check "show access-lists: 20 ... (1 match)" grep -q '^    20 deny udp any any eq 9999 log-input (1 match)$' $WORK/show
	check "show access-lists WEB interface ab0" eval 'CTL show access-lists WEB interface ab0 | grep -q "30 permit ip any any (1 match)"'
	check "show ip access-lists" eval 'CTL show ip access-lists | grep -q "^Extended IP access list WEB"'
	check "unknown list: exit 1" eval '! CTL show access-lists NOPE >/dev/null'
	for _ in $(seq 30); do grep -q 9999 $D/run/acl.log 2>/dev/null && break; sleep 0.1; done
	check "log: one line for the flow (first packet only)" [ "$(grep -c 'tcp 10.9.0.1(4321) -> 10.0.0.9(80)' $D/run/acl.log 2>/dev/null)" = 1 ]
	check "log: IOS format" grep -q '%SEC-6-IPACCESSLOGP: list WEB permitted tcp 10.9.0.1(4321) -> 10.0.0.9(80), 1 packet' $D/run/acl.log
	check "log-input: interface and MAC" grep -q "list WEB denied udp 10.9.0.7(53) (ab0 $(echo $AMAC | tr -d : | sed 's/\(....\)\(....\)/\1.\2./')) -> 10.0.0.9(9999)" $D/run/acl.log
	check "log: in the journal too" grep -q 'IPACCESSLOGP: list WEB' $WORK/bpfcd.log
	check "bpfcctl log" eval 'CTL log | grep -q "list WEB denied"'
	( for _ in $(seq 8); do send proto=tcp,src=10.9.0.2,dst=10.0.0.9,dport=80,tcpflags=16,count=20; done ) &
	SPID=$!
	CTL top 5 1 > $WORK/top
	wait $SPID
	check "top: the busy entry first" eval 'sed -n 2p $WORK/top | grep -q " WEB .* 10 .*permit tcp any any eq 80"'
	CTL clear access-list counters WEB
	check "clear access-list counters" eval '! CTL show access-lists WEB | grep -q matches'
	kill $DPID; wait $DPID 2>/dev/null; DPID=
else
	test_skip "bpfcd (not built)"
fi

echo "== the examples (dist/examples/acl) load"
EX=$WORK/ex
mkdir -p $EX && cp -r dist/examples/acl/acl.d $EX/ && chmod -R a+rX $EX
for f in dist/examples/acl/*.acl; do
	cp $f $WORK/ex.acl
	sed -i '/^interface /d' $WORK/ex.acl          # servers-in.acl names eth1
	d=ingress; case $f in *-out.acl) d=egress ;; esac
	check "example $(basename $f)" B env BPFC_CONF_ROOT=$EX $BPFC -m $MAPS -i ab0 -d $d -T -f $WORK/ex.acl
done

echo "== errors name what IOS has and bpfc does not"
e() { local name=$1; shift; printf '%s\n' "$@" > $WORK/bad.acl; reject "$name" -f $WORK/bad.acl; }
e "time-range"  "ip access-list extended X" " permit ip any any time-range WORK"
e "missing wildcard" "ip access-list extended X" " permit ip 10.0.0.0 any"
e "port on ip"  "ip access-list extended X" " permit ip any any eq 80"
e "unknown list" "ip access-group NOPE in"
e "wrong direction" "ip access-list extended X" " permit ip any any" "ip access-group X out"
e "two v4 lists" "ip access-list extended X" " permit ip any any" "ip access-list extended Y" " permit ip any any"
e "fragments + ports" "ip access-list extended X" " permit tcp any any eq 80 fragments"
e "established on udp" "ip access-list extended X" " permit udp any any established"
e "duplicate seq" "ip access-list extended X" " 10 permit ip any any" " 10 deny ip any any"
e "mac out" "mac access-list extended M" " permit any any" "mac access-group M out"
e "type mismatch" "ipv6 access-list X" " permit ipv6 any any" "ip access-group X in"

[ -n "$ACL_DEBUG" ] && { $BPFC -m $MAPS -r BPFC_ACL_P | head; cat $WORK/meta | head -3; }
tests_exit
