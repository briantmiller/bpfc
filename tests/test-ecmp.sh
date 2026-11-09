#!/bin/bash
# End-to-end tests of the bandwidth-aware ECMP layer (ecmp/). Needs root.
#
#   H --eth0-- R --eth1-- N (10.1.0.2)   member
#              +--eth2-- N (10.2.0.2)   member
#              +--eth3-- N (10.3.0.2)   member (ECMP or a less specific route)
#              +--tun0                  member, tunnel
# Traffic goes H -> R -> the other side of one of the links.
cd "$(dirname "$0")/.." || exit 1
. tests/lib.sh
require_root ecmp
require_cmds ecmp ip python3 tc gawk

BPFC=$PWD/bpfc; GEN=$PWD/ecmp/bpfc-ecmp-gen; STATUS=$PWD/ecmp/bpfc-ecmp-status
[ -x "$BPFC" ] || { test_fail "bpfc is built"; tests_exit; }
T=$(mktemp -d /tmp/bpfc-ecmp.XXXXXX)
R="ip netns exec ecR"; H="ip netns exec ecH"
SEND="python3 $PWD/tests/ecmp-send.py"; CAP="python3 $PWD/tests/ecmp-capture.py"
TUNPID=
cleanup() { [ -z "$TUNPID" ] || kill "$TUNPID" 2>/dev/null; ip netns del ecR 2>/dev/null; ip netns del ecH 2>/dev/null; umount "$T/m" 2>/dev/null; rm -rf "$T"; }
trap 'cleanup; rm -f "$TESTS_FAILED_FILE"' EXIT
ulimit -l unlimited 2>/dev/null

# ---------------------------------------------------------------- generator
gen_err() { # name, expected message, args...
	local n=$1 m=$2; shift 2
	local o; o=$("$GEN" -o "$T/e" "$@" 2>&1)
	if [ $? -ne 0 ] && grep -q -- "$m" <<< "$o"; then test_pass "generator: $n"; else test_fail "generator: $n ($o)"; fi
}
BASE=(-M a=1g -M b=1g -I c)
gen_err "one member refused" "at least two" -M a=1g -I c
gen_err "no ingress refused" "at least one --ingress" -M a=1g -M b=1g
gen_err "bad rate refused" "not a rate" -M a=fast -M b=1g -I c
gen_err "bad mode refused" "--mode: one of" "${BASE[@]}" --mode l9
gen_err "clear below move" "must be below" "${BASE[@]}" --move 80 --clear 80
gen_err "shed not above move" "must not be above" "${BASE[@]}" --shed 95 --move 90 --force 95 --clear 80
gen_err "policy interface must be a member" "not a member" "${BASE[@]}" --policy "src 10.0.0.0/8 prefer z"
gen_err "ports need an l4 mode" "needs a mode" "${BASE[@]}" --mode l3 --policy "dport 80 prefer a"
gen_err "policy needs prefer" "no prefer" "${BASE[@]}" --policy "src 10.0.0.0/8"
gen_err "too many members" "at most" -M a=1g -M b=1g -M c1=1g -M d=1g -M e=1g -M f=1g -M g=1g -M h=1g -M i=1g -I c
o=$("$GEN" -o "$T/g0" -M a=1g -M b=2g -I c,a --mode l3 2>&1) && [ -f "$T/g0/c/ingress/400.bpfc" ] && [ -f "$T/g0/a/ingress/400.bpfc" ] \
	&& [ -f "$T/g0/a/egress/400.bpfc" ] && [ -f "$T/g0/b/ingress/400.bpfc" ] && [ ! -f "$T/g0/c/egress/400.bpfc" ]
check "generator: writes each program where it belongs" test $? -eq 0
grep -q 'cap=2000000000' "$T/g0/b/egress/400.bpfc"; check "generator: records the bandwidth" test $? -eq 0
grep -q 'role=rx' "$T/g0/b/ingress/400.bpfc"; check "generator: a member that does not steer only counts" test $? -eq 0
grep -q 'role=selector' "$T/g0/a/ingress/400.bpfc"; check "generator: a member can also steer" test $? -eq 0
"$GEN" -o "$T/g1" -M a=1g -M b=2g -I c,a --mode l3 >/dev/null 2>&1; diff -r "$T/g0" "$T/g1" >/dev/null
check "generator: output is reproducible" test $? -eq 0
"$GEN" --list-profiles | grep -q wan; check "generator: lists profiles" test $? -eq 0
"$GEN" --profile-dir "$PWD/ecmp/profiles" --show-profile wan | grep -q 'shed.*profile wan'; check "generator: shows a profile" test $? -eq 0

# ---------------------------------------------------------------- topology
ip netns del ecR 2>/dev/null; ip netns del ecH 2>/dev/null
ip netns add ecR; ip netns add ecH
for n in ecR ecH; do ip -n $n link set lo up; ip netns exec $n sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null; done
ip link add h0 netns ecH type veth peer name eth0 netns ecR
i=1; for e in eth1 eth2 eth3; do
	ip link add p$i netns ecH type veth peer name $e netns ecR
	ip -n ecR addr add 10.$i.0.1/24 dev $e; ip -n ecR link set $e up
	ip -n ecH link set p$i up
	$H sysctl -qw net.ipv4.conf.p$i.rp_filter=0
	i=$((i + 1))
done
ip -n ecR addr add 192.168.1.1/24 dev eth0; ip -n ecR link set eth0 up
ip -n ecH addr add 192.168.1.2/24 dev h0; ip -n ecH link set h0 up
ip -n ecH route add default via 192.168.1.1
$R sysctl -qw net.ipv4.ip_forward=1 net.ipv4.fib_multipath_hash_policy=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
for e in eth0 eth1 eth2 eth3; do $R sysctl -qw net.ipv4.conf.$e.rp_filter=0; done
$H sysctl -qw net.ipv4.ip_forward=0
$H ethtool -K h0 tx off >/dev/null 2>&1
for i in 1 2 3; do ip -n ecR neigh replace 10.$i.0.2 lladdr "$($H cat /sys/class/net/p$i/address)" dev eth$i nud permanent; done
ip -n ecH neigh replace 192.168.1.1 lladdr "$($R cat /sys/class/net/eth0/address)" dev h0 nud permanent
mkdir -p "$T/m"; mount -t bpf bpffs "$T/m"
for x in eth0 eth1 eth2 eth3; do $R tc qdisc add dev $x clsact 2>/dev/null; done

st() { $R env BPFC="$BPFC" "$STATUS" -m "$T/m" -c "$T/p" "$@"; }
ctr() { st counters | awk -v k="$1" '$1==k{print $2}'; }
rx() { $H cat /sys/class/net/p$1/statistics/rx_packets; }
set_ecmp() { # members in the route, e.g. "1 2"
	local a="" i
	for i in "$@"; do a="$a nexthop via 10.$i.0.2 dev eth$i"; done
	$R ip route replace 10.9.9.0/24 $a
}
# gen_load <generator args>: fresh maps and programs, then tell them the members
gen_load() {
	local p
	for x in eth0 eth1 eth2 eth3 tun0; do $R tc filter del dev $x ingress pref 400 2>/dev/null; $R tc filter del dev $x egress pref 400 2>/dev/null; done
	rm -f "$T"/m/ec_*; rm -rf "$T/p"
	"$GEN" -o "$T/p" -P ec "$@" >"$T/gen.out" 2>&1 || { cat "$T/gen.out"; return 1; }
	local rc=0
	for p in "$T"/p/*/*/400.bpfc; do
		local d=${p%/400.bpfc}; local dir=${d##*/}; d=${d%/*}; local dev=${d##*/}
		$R "$BPFC" -m "$T/m" -i "$dev" -d "$dir" -p 400 -f "$p" >"$T/load.out" 2>&1 || { tail -3 "$T/load.out"; rc=1; }
	done
	[ $rc -eq 0 ] || return 1
	st -P ec sync
}
st() { $R env BPFC="$BPFC" "$STATUS" -P ec -m "$T/m" -c "$T/p" "$@"; }
MEMBERS=(-M eth1=1g -M eth2=1g -M eth3=1g -I eth0)

# fib-lookup ports reaches each next hop, chosen by the value alone
set_ecmp 1 2
$R ip route replace default via 10.3.0.2 dev eth3
cat > "$T/ports.bpfc" <<'EOF'
match ip; match udp;
  decl D 4; get ip-dst D;
  decl V 4; set val V 0;
  repeat 64 as I;
    set val V $(I * 104729);
    fib-lookup ports %V %D;
    calc-map add PORTSEEN %FIB_IFINDEX 1;
  end-repeat;
end-match; end-match;
drop;
EOF
$R "$BPFC" -m "$T/m" -i eth0 -p 300 -f "$T/ports.bpfc" >/dev/null 2>&1 \
	&& $H $SEND flows 1 --count 1 && sleep 0.2
s=$($R "$BPFC" -m "$T/m" -r PORTSEEN | grep -c 'Key:')
i1=$($R cat /sys/class/net/eth1/ifindex); i2=$($R cat /sys/class/net/eth2/ifindex); i3=$($R cat /sys/class/net/eth3/ifindex)
d=$($R "$BPFC" -m "$T/m" -r PORTSEEN)
check "fib-lookup ports: finds both next hops" test "$s" = 2
grep -q "Key: 0x0*$(printf %x $i3) " <<< "$d"; check "fib-lookup ports: never the less specific route" test $? -ne 0
$R "$BPFC" -i eth0 -p 300 -D >/dev/null 2>&1

# ---------------------------------------------------------------- load
gen_load "${MEMBERS[@]}"; check "programs load (l4, 3 members)" test $? -eq 0
for mode in l3 l3+tos l3+proto l4+tos l3-sym l4-sym; do
	gen_load "${MEMBERS[@]}" --mode $mode; check "programs load (mode $mode)" test $? -eq 0
done
M8=(); for i in 1 2 3 4 5 6; do M8+=(-M x$i=1g); done
"$GEN" -o "$T/g8" -P e8 "${M8[@]}" -I eth0 --policy "src 10.0.0.0/8 prefer x1,x2" --policy "dscp 46 prefer x3,x4 strict" --policy "dport 443 prefer x5" >/dev/null 2>&1
o=$($R "$BPFC" -m "$T/m" -s IFNAME=eth0 -i eth0 -p 300 -I -f "$T/g8/eth0/ingress/400.bpfc" 2>&1); rc=$?
v=$(sed -n 's/.*verified=\([0-9]*\).*/\1/p' <<< "$o")
if [ $rc -eq 0 ]; then test_pass "programs load (6 members, 3 policies, $v verified)"; else test_fail "programs load (6 members, 3 policies): $(tail -2 <<< "$o")"; fi
$R "$BPFC" -i eth0 -p 300 -D >/dev/null 2>&1
rm -f "$T"/m/e8_*

# ---------------------------------------------------------------- spreading
set_ecmp 1 2
gen_load "${MEMBERS[@]}"
a1=$(rx 1); a2=$(rx 2); a3=$(rx 3)
$H $SEND flows 400 --count 3; sleep 0.3
d1=$(( $(rx 1) - a1 )); d2=$(( $(rx 2) - a2 )); d3=$(( $(rx 3) - a3 ))
check "flows spread over both members ($d1 / $d2)" test "$d1" -gt 300 -a "$d2" -gt 300
check "the route is respected: none on the non-member link ($d3)" test "$d3" -eq 0
check "every packet was forwarded ($((d1 + d2)) of 1200)" test $((d1 + d2)) -eq 1200
check "flows recorded" test "$(ctr new_flows)" = 400

# Consistency per mode: one interface per flow.
consistent() { # mode, flows, sender args...: each key seen on one interface
	local mode=$1 n=$2; shift 2
	$H $CAP -t 1.5 p1 p2 p3 > "$T/cap" &
	local p=$!
	sleep 0.3
	$H $SEND flows "$n" "$@"
	sleep 0.2
	$H $SEND flows "$n" "$@"
	wait $p
	awk -v mode="$mode" '$1 ~ /^p[123]$/ {
		k = (mode ~ /^l3/) ? $4 ">" $5 : $4 ":" $7 ">" $5 ":" $8
		if (mode ~ /tos/) k = k "/" $10
		if (k in w && w[k] != $1) bad++
		w[k] = $1; n++
	} END { exit !(n > 0 && bad == 0) }' "$T/cap"
}
consistent l4 40 --count 4; check "l4: packets of a flow stay on one interface" test $? -eq 0
gen_load "${MEMBERS[@]}" --mode l3
consistent l3 40 --count 4; check "l3: all ports between two addresses share an interface" test $? -eq 0
new=$(ctr new_flows); check "l3: one flow per address pair ($new; a second if two CPUs raced)" test "$new" -ge 1 -a "$new" -le 2
gen_load "${MEMBERS[@]}" --mode l3+tos
$H $SEND flows 1 --count 1 --tos 0; sleep 0.05; $H $SEND flows 1 --count 1 --tos 184; sleep 0.05; $H $SEND flows 1 --count 1 --tos 184 --sport 3000; sleep 0.05
check "l3+tos: DSCP makes a flow, ports do not" test "$(ctr new_flows)" = 2
gen_load "${MEMBERS[@]}" --mode l3-sym
$R ip route replace 10.9.8.0/24 nexthop via 10.1.0.2 dev eth1 nexthop via 10.2.0.2 dev eth2
$H $SEND raw 10.9.8.1 10.9.9.1 --count 1; sleep 0.1; $H $SEND raw 10.9.9.1 10.9.8.1 --count 1; sleep 0.1
n=$(ctr new_flows); check "l3-sym: both directions are one flow ($n)" test "$n" = 1
$R ip route del 10.9.8.0/24

# Fragments of a datagram stay together in l4 mode (no ports to hash on).
set_ecmp 1 2
gen_load "${MEMBERS[@]}"
$H $CAP -t 1.2 p1 p2 > "$T/cap" &
p=$!; sleep 0.3
$H $SEND flows 30 --count 2 --size 3000 --sport 2500
wait $p
n=$(awk '$6==17' "$T/cap" | cut -d' ' -f1 | sort -u | wc -l)
t=$(awk '$6==17' "$T/cap" | wc -l)
check "fragments stay on one interface ($t packets, $n interface)" test "$n" -eq 1 -a "$t" -gt 100

# ---------------------------------------------------------------- nothing but routing changes the packet
set_ecmp 1 2
gen_load "${MEMBERS[@]}"
$H $CAP -t 1.2 p1 p2 > "$T/cap" &
p=$!; sleep 0.3
$H $SEND flows 8 --count 2 --tos 72 --size 300 --dport 5001
wait $p
n=$(awk '$8==5001' "$T/cap" | wc -l)
check "packets captured at the far side ($n)" test "$n" -eq 16
awk '$8==5001 && ($9!=63 || $10!=72 || $11!=328 || $12!=1) {bad=1} END{exit bad}' "$T/cap"
check "TTL lowered by one, checksum valid, TOS and length untouched" test $? -eq 0
awk '$8==5001 && $13!="7878787878787878" {bad=1} END{exit bad}' "$T/cap"
check "payload untouched" test $? -eq 0
m1=$($R cat /sys/class/net/eth1/address | tr -d :); m2=$($R cat /sys/class/net/eth2/address | tr -d :)
d1=$($H cat /sys/class/net/p1/address | tr -d :); d2=$($H cat /sys/class/net/p2/address | tr -d :)
awk -v m1="$m1" -v m2="$m2" -v d1="$d1" -v d2="$d2" '$8==5001 { if ($1=="p1" && ($2!=m1 || $3!=d1)) bad=1; if ($1=="p2" && ($2!=m2 || $3!=d2)) bad=1 } END{exit bad}' "$T/cap"
check "MACs are the router's and the next hop's" test $? -eq 0

# Left to the kernel: TTL 1 gets its ICMP, the router's own addresses get answered.
if command -v ping >/dev/null; then
	$H ping -c1 -W2 -t1 10.9.9.9 2>&1 | grep -qi 'time.*exceeded'; check "TTL 1 goes to the kernel" test $? -eq 0
	$H ping -c1 -W2 192.168.1.1 >/dev/null 2>&1; check "traffic to the router itself is delivered" test $? -eq 0
else
	test_skip "kernel handling of TTL 1 and local traffic (no ping)"
fi

# ---------------------------------------------------------------- the route is checked on every packet
set_ecmp 1 2
$R ip route replace default via 10.2.0.2 dev eth2      # eth2 stays reachable by a less specific route
gen_load "${MEMBERS[@]}"
$H $SEND flows 60 --count 2; sleep 0.2
set_ecmp 1 3
a2=$(rx 2); a1=$(rx 1); a3=$(rx 3)
$H $SEND flows 60 --count 3; sleep 0.2
d2=$(( $(rx 2) - a2 )); d1=$(( $(rx 1) - a1 )); d3=$(( $(rx 3) - a3 ))
check "a withdrawn member gets nothing, even with a less specific route ($d2)" test "$d2" -eq 0
check "its flows moved to the remaining members at once ($d1 + $d3 = 180)" test $((d1 + d3)) -eq 180
n=$(ctr route_changes); check "route changes counted ($n)" test "${n:-0}" -gt 0
check "both remaining members took some ($d1 / $d3)" test "$d3" -gt 0 -a "$d1" -gt 0
st events | grep -q 'route-change'; check "the event log shows it" test $? -eq 0
$R ip route replace default via 10.3.0.2 dev eth3
set_ecmp 1 2
gen_load "${MEMBERS[@]}"
$H $SEND flows 20 --count 1
$R ip route del 10.9.9.0/24
$R ip route add blackhole 10.9.9.0/24
a=$(( $(rx 1) + $(rx 2) ))
$H $SEND flows 20 --count 2; sleep 0.1
d=$(( $(rx 1) + $(rx 2) - a ))
check "a route gone entirely: nothing forwarded ($d)" test "$d" -eq 0
$R ip route del blackhole 10.9.9.0/24

# A new member rehashes the route; flows on members that are still there stay.
set_ecmp 1 2
gen_load "${MEMBERS[@]}"
$H $SEND flows 100 --count 1 --sport 9000; sleep 0.1
st -j flows -n 0 > "$T/f0"
set_ecmp 1 2 3
$H $SEND flows 100 --count 1 --sport 9000; sleep 0.1
st -j flows -n 0 > "$T/f1"
diff <(python3 -c 'import json; print(sorted((f["src"],f["interface"]) for f in json.load(open("'"$T/f0"'"))))') \
     <(python3 -c 'import json; print(sorted((f["src"],f["interface"]) for f in json.load(open("'"$T/f1"'"))))') >/dev/null
check "a new member does not disturb existing flows" test $? -eq 0
k=$(ctr kept_after_route_change); check "flows were re-checked and kept ($k)" test "${k:-0}" -gt 0

# ---------------------------------------------------------------- bandwidth
set_ecmp 1 2
gen_load -M eth1=10m -M eth2=20m -M eth3=1g -I eth0 --shed 70 --move 90 --clear 80
st bw | grep -E 'eth1 +10000000 generated' >/dev/null; check "bw shows the generated value" test $? -eq 0
b=$(st bw eth2); check "bw reads one interface ($b)" test "$b" = 20000000
st bw eth2 50m; b=$(st bw eth2); check "bw writes one interface ($b)" test "$b" = 50000000
st bw | grep -E 'eth2 +50000000 map' >/dev/null; check "bw says where it comes from" test $? -eq 0
$H $SEND rate 2e6 1.5 --flows 4 --size 800 --sport 2100 &
sleep 1.2
c=$(st -j status | python3 -c 'import sys,json; d=json.load(sys.stdin); print([m for m in d if m["interface"]=="eth2"][0]["bandwidth"])')
check "the map value is used ($c)" test "$c" = 50000000
wait
st bw eth2 default; b=$(st bw eth2); check "bw default restores it ($b)" test "$b" = 20000000
python3 -c 'import sys,json; json.load(sys.stdin)' < <(st -j settings); check "settings JSON parses" test $? -eq 0
python3 -c 'import sys,json; json.load(sys.stdin)' < <(st -j counters); check "counters JSON parses" test $? -eq 0
st set shed 55; st settings | grep -qE '^shed +55%'; check "set changes a setting" test $? -eq 0
st unset shed; st settings | grep -qE '^shed +70%'; check "unset returns to the generated value" test $? -eq 0

# Rates: one flow at a known rate, on an interface at a known bandwidth.
gen_load -M eth1=20m -M eth2=20m -M eth3=1g -I eth0
$H $SEND rate 8e6 2.5 --size 1000 --sport 2200 &
sleep 2.2
fl=$(st -j flows | python3 -c 'import sys,json; d=[f for f in json.load(sys.stdin) if f["src"].endswith(":2200")]; print(d[0]["bps"] if d else 0)')
s=$(st -j status | python3 -c 'import sys,json; print(max(m["utilisation_pct"] for m in json.load(sys.stdin)))')
wait
check "flow bit/s is close to the true 8 Mbit/s ($fl)" test "$fl" -gt 6500000 -a "$fl" -lt 9500000
ok=$(awk -v s="$s" 'BEGIN{print (s>30 && s<50)?1:0}'); check "utilisation of a 20 Mbit/s link near 40 % ($s %)" test "$ok" = 1
st flows | grep -q ':2200'; check "flows lists it" test $? -eq 0

# ---------------------------------------------------------------- shedding
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 90 --clear 80 --mode l4
# Everything from this source prefers eth1, until it fills up.
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 99 --clear 80 --force 100 \
	--policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
$H $SEND rate 7e6 2.5 --flows 2 --size 1000 --dport 6000 --sport 2300 &
sleep 1.5
a1=$(rx 1); a2=$(rx 2)
$H $SEND flows 20 --count 2 --dport 6000 --sport 3000
sleep 0.2
wait
st flows -n 0 | awk '/:6000/ && $1 ~ /:30[0-9][0-9]$/ {c[$5]++} END{for (k in c) print k, c[k]}' > "$T/shed"
e1=$(awk '$1=="eth1"{print $2}' "$T/shed"); e2=$(awk '$1=="eth2"{print $2}' "$T/shed")
check "new flows avoid a member above shed (${e1:-0} on it, ${e2:-0} elsewhere)" test "${e1:-0}" -eq 0 -a "${e2:-0}" -eq 20
n=$(st counters | awk '$1=="policy_placed"{print $2}'); check "they were placed by the policy ($n)" test "${n:-0}" -gt 20

# Without any policy: what hashes to a full member goes elsewhere.
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 99 --clear 80 --force 100 \
	--policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
$H $SEND rate 7e6 2.5 --flows 2 --size 1000 --dport 6000 --sport 2300 &
sleep 1.5
$H $SEND flows 60 --count 2 --sport 3100
sleep 0.2; wait
st flows -n 0 | awk '$1 ~ /:31[0-9][0-9]$/ {c[$5]++} END{print c["eth1"]+0, c["eth2"]+0}' > "$T/shed"
read -r e1 e2 < "$T/shed"
check "hashed flows avoid a member above shed ($e1 on it, $e2 elsewhere)" test "$e1" -eq 0 -a "$e2" -eq 60
n=$(ctr shed_to_other); check "counted as shed ($n)" test "${n:-0}" -gt 0
st events | grep -q ' shed '; check "the event log shows shedding" test $? -eq 0

# Balanced placement weighs free capacity.
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --place balanced
$H $SEND rate 4e6 2 --size 1000 --sport 3200 --flows 40 &
sleep 1.5
st status > "$T/s"; wait
st flows -n 0 | awk '$1 ~ /:32[0-9][0-9]$/ {c[$5]++} END{print c["eth1"]+0, c["eth2"]+0}' > "$T/bal"
read -r e1 e2 < "$T/bal"
check "balanced: the bigger link gets more flows ($e1 / $e2)" test "$e2" -gt "$e1"

# ---------------------------------------------------------------- moving existing flows
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 90 --clear 80 --force 95 --elephant 1m --dwell 2s --move-interval 200ms \
	--policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
$H $SEND rate 12e6 4 --flows 3 --size 1000 --dport 6000 --sport 2400 &
sleep 3
st status > "$T/s"
st -j flows -n 0 > "$T/f"
wait
n=$(ctr moved); check "elephants moved off an overloaded member ($n)" test "${n:-0}" -ge 1
st events | grep -q 'moved'; check "the event log shows the move" test $? -eq 0
on2=$(python3 -c 'import json; d=json.load(open("'"$T/f"'")); print(sum(1 for f in d if f["interface"]=="eth2" and ":24" in f["src"]))')
check "at least one flow left ($on2)" test "$on2" -ge 1
n3=$(python3 -c 'import json; d=json.load(open("'"$T/f"'")); print(sum(1 for f in d if f["interface"]=="eth1" and ":24" in f["src"]))')
check "not all had to leave ($n3 stayed)" test "$n3" -ge 1
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 90 --clear 80 --force 95 --no-move eth1 --policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
$H $SEND rate 12e6 3 --flows 3 --size 1000 --dport 6000 --sport 2500 &
sleep 2.5; n=$(ctr moved); wait
check "--no-move keeps flows where they are ($n)" test "${n:-0}" -eq 0
gen_load -M eth1=10m -M eth2=1g -M eth3=1g -I eth0 --shed 50 --move 90 --clear 80 --force 95 --moves off --policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
$H $SEND rate 12e6 3 --flows 3 --size 1000 --dport 6000 --sport 2600 &
sleep 2.5; n=$(ctr moved); wait
check "--moves off too ($n)" test "${n:-0}" -eq 0
# Moves never go somewhere without room.
gen_load -M eth1=10m -M eth2=10m -M eth3=1g -I eth0 --shed 50 --move 90 --clear 80 --force 95 --dwell 500ms --move-interval 200ms --policy "src 192.168.1.2/32 dport 6000 prefer eth1,eth2"
a1=$(rx 1); a2=$(rx 2)
$H $SEND rate 12e6 2.5 --dport 6000 --sport 2700 --size 1000
sleep 0.2
n=$(ctr moved); d1=$(( $(rx 1) - a1 )); d2=$(( $(rx 2) - a2 ))
check "no room anywhere: the flow stays ($n moves)" test "${n:-0}" -eq 0
check "and is not sent the wrong way by the search ($d1 on eth1, $d2 on eth2)" test "$d2" -eq 0 -a "$d1" -gt 1000

# ---------------------------------------------------------------- policy
set_ecmp 1 2
$R ip route replace default via 10.3.0.2 dev eth3
gen_load -M eth1=1g -M eth2=1g -M eth3=1g -I eth0 --policy "src 192.168.1.0/24 dscp 46 prefer eth2,eth1" --policy "src 192.168.1.0/24 dscp 10 prefer eth3,eth1 strict"
a1=$(rx 1); a2=$(rx 2); a3=$(rx 3)
$H $SEND flows 40 --count 3 --tos 184 --sport 4000; sleep 0.2
d1=$(( $(rx 1) - a1 )); d2=$(( $(rx 2) - a2 )); d3=$(( $(rx 3) - a3 ))
check "policy: subnet + DSCP go to the first choice ($d2 of 120)" test "$d2" -eq 120 -a "$d1" -eq 0
st flows -n 0 | awk '/:40[0-9][0-9] / && $10!="policy"{b=1} END{exit b}'; check "policy: recorded as the decision" test $? -eq 0
a1=$(rx 1); a2=$(rx 2); a3=$(rx 3)
$H $SEND flows 20 --count 3 --sport 4100; sleep 0.2
d3=$(( $(rx 3) - a3 ))
check "unmatched traffic still only uses the members ($d3 on eth3)" test "$d3" -eq 0
a1=$(rx 1); a3=$(rx 3); a2=$(rx 2)
$H $SEND flows 20 --count 3 --tos 40 --sport 4200; sleep 0.2
d1=$(( $(rx 1) - a1 )); d3=$(( $(rx 3) - a3 ))
check "policy: an interface that is not a next hop is skipped ($d3 on eth3, $d1 on eth1)" test "$d3" -eq 0 -a "$d1" -eq 60
set_ecmp 1
a2=$(rx 2); a1=$(rx 1)
$H $SEND flows 40 --count 2 --tos 184 --sport 4000; sleep 0.2
d2=$(( $(rx 2) - a2 )); d1=$(( $(rx 1) - a1 ))
check "policy: preferred member withdrawn, the next is used ($d1 on eth1, $d2 on eth2)" test "$d2" -eq 0 -a "$d1" -eq 80
gen_load -M eth1=1g -M eth2=1g -M eth3=1g -I eth0 --policy "src 192.168.1.0/24 dscp 10 prefer eth2 strict"
set_ecmp 1
a=$(( $(rx 1) + $(rx 2) ))
$H $SEND flows 10 --count 3 --tos 40 --sport 4300; sleep 0.2
d=$(( $(rx 1) + $(rx 2) - a ))
check "strict: dropped when no listed interface is a next hop ($d)" test "$d" -eq 0
n=$(ctr strict_dropped); check "strict drops counted ($n)" test "${n:-0}" -gt 0
# The way back: a preferred member returns, flows follow at their next pause.
set_ecmp 1 2
gen_load -M eth1=1g -M eth2=1g -M eth3=1g -I eth0 --gap 20ms --dwell 100ms --policy "src 192.168.1.0/24 dscp 46 prefer eth2,eth1"
set_ecmp 1
$H $SEND flows 4 --count 3 --tos 184 --sport 4400 --gap 0.05; sleep 0.1
set_ecmp 1 2; sleep 0.1
$H $SEND flows 4 --count 8 --tos 184 --sport 4400 --gap 0.3; sleep 0.1
n=$(ctr back_to_preferred); check "flows return to the preferred member ($n)" test "${n:-0}" -ge 1
st flows -n 0 | awk '/:44[0-9][0-9] / {c++; if ($5!="eth2") b=1} END{exit (b||!c)}'
check "they end up on it" test $? -eq 0

# ---------------------------------------------------------------- a full table
gen_load "${MEMBERS[@]}" --flows 256
a=$(( $(rx 1) + $(rx 2) ))
$H $SEND flows 600 --count 2 --sport 7000; sleep 0.3
d=$(( $(rx 1) + $(rx 2) - a ))
check "a full flow table costs no packets ($d of 1200)" test "$d" -eq 1200
n=$(ctr table_full); check "and is counted ($n)" test "${n:-0}" -gt 0

# ---------------------------------------------------------------- tunnels
if $R ip tuntap add mode tun name tun0 2>/dev/null; then
	$R ip link set tun0 up; $R ip addr add 172.16.0.1/30 dev tun0
	$R tc qdisc add dev tun0 clsact 2>/dev/null
	$R sysctl -qw net.ipv4.conf.tun0.rp_filter=0
	$R python3 - "$T/tun.out" <<'PY' &
import fcntl, os, select, socket, struct, sys, time
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"tun0", 0x0001 | 0x1000))  # IFF_TUN | IFF_NO_PI
out = open(sys.argv[1], "w"); end = time.time() + 40
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        d = os.read(fd, 65535)
        if d[0] >> 4 != 4 or d[9] != 17: continue
        print(socket.inet_ntoa(d[12:16]), socket.inet_ntoa(d[16:20]), d[8], struct.unpack("!H", d[22:24])[0], d[28:36].hex(), flush=True, file=out)
PY
	TUNPID=$!
	sleep 0.5
	$R ip route replace 10.9.9.0/24 nexthop dev tun0 nexthop via 10.1.0.2 dev eth1
	gen_load -M tun0=100m -M eth1=1g -M eth2=1g -I eth0
	a1=$(rx 1); : > "$T/tun.out"
	$H $SEND flows 200 --count 2 --sport 8000 --dport 5002; sleep 0.5
	d1=$(( $(rx 1) - a1 )); tn=$(grep -c ' 5002 ' "$T/tun.out")
	check "tunnel: flows on it and on the Ethernet member ($tn + $d1 = 400)" test "$tn" -gt 80 -a "$d1" -gt 80 -a $((tn + d1)) -eq 400
	awk '$3!=63 || $5!="7878787878787878" {b=1} END{exit b}' "$T/tun.out"
	check "tunnel: arrives as plain IP, TTL lowered, payload untouched" test $? -eq 0
	st status | grep -E '^tun0' | grep -qE ' ok'; check "tunnel: measured like any member" test $? -eq 0
	$R ip route replace 10.9.9.0/24 nexthop via 10.2.0.2 dev eth2 nexthop via 10.1.0.2 dev eth1
	: > "$T/tun.out"
	$H $SEND flows 100 --count 2 --sport 8000 --dport 5002; sleep 0.4
	tn=$(grep -c ' 5002 ' "$T/tun.out")
	check "tunnel: withdrawn, it gets nothing ($tn)" test "$tn" -eq 0
	kill "$TUNPID" 2>/dev/null; TUNPID=
else
	test_skip "tunnel members (no tun device)"
fi
gen_err "tunnel ingress refused" "only Ethernet" -M a=1g -M b=1g -I lo

# ---------------------------------------------------------------- under bpfcd
if [ -x "$PWD/bpfcd/bpfcd" ]; then
	for x in eth0 eth1 eth2 eth3 tun0; do $R tc filter del dev $x ingress pref 400 2>/dev/null; $R tc filter del dev $x egress pref 400 2>/dev/null; done
	rm -f "$T"/m/ec_*
	mkdir -p "$T/etc/interfaces.d" "$T/run"
	cat > "$T/etc/bpfc.conf" <<EOF
config_dir = $T/etc/interfaces.d
map_dir = $T/m
state_dir = $T/run
bpfc_path = $BPFC
EOF
	"$GEN" -o "$T/etc/interfaces.d" -P ec "${MEMBERS[@]}" >/dev/null 2>&1
	$R "$PWD/bpfcd/bpfcd" -c "$T/etc/bpfc.conf" >"$T/bpfcd.log" 2>&1 &
	DP=$!
	for _ in $(seq 100); do [ -n "$($R tc filter show dev eth0 ingress pref 400 2>/dev/null)" ] && [ -n "$($R tc filter show dev eth3 egress pref 400 2>/dev/null)" ] && break; sleep 0.1; done
	set_ecmp 1 2
	$R tc filter show dev eth0 ingress pref 400 2>/dev/null | grep -q bpfcd
	check "bpfcd installs the generated tree" test $? -eq 0
	$H $SEND flows 5 --count 3 --sport 9500; sleep 0.2
	a=$(( $(rx 1) + $(rx 2) ))
	$H $SEND flows 100 --count 3 --sport 9600; sleep 0.3
	d=$(( $(rx 1) + $(rx 2) - a ))
	check "and it forwards ($d of 300)" test "$d" -eq 300
	n=$($R env BPFC="$BPFC" "$STATUS" -P ec -m "$T/m" -c "$T/etc/interfaces.d" counters | awk '$1=="new_flows"{print $2}')
	check "and is seen by the status tool ($n flows)" test "${n:-0}" -gt 90
	kill "$DP" 2>/dev/null; wait "$DP" 2>/dev/null
fi

tests_exit
