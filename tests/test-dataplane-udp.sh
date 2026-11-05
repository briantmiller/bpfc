#!/bin/bash
# End-to-end tests for the dataplane's UDP carriers (carrier udp and
# udp-inline). Three namespaces:
#
#   A (site 1, 10.1.0.1) ua0 192.0.2.1 --- ur0 192.0.2.254  R  ur1 100.64.0.1 --- ub0 100.64.0.2 B (site 2, 10.2.0.1)
#
# R routes between the two and, for carrier udp, masquerades B (B is behind
# carrier-grade NAT, A learns B's address and port from its packets); R has
# no route to the site prefixes, so they only get through inside the
# carrier. For udp-inline R routes the site prefixes (a private WAN) and
# does no NAT. Loss is added by a bpfc program on the receiving interface's
# ingress, ahead of the dataplane.
#
#   sudo bash tests/test-dataplane-udp.sh [-k]      (-k: keep namespaces)
#
# Needs: ip, ethtool, ping, nc, nft, cmp, python3.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
BPFC=$PWD/bpfc
GEN=$PWD/dataplane/bpfc-dataplane-gen
STATUS="env BPFC=$PWD/bpfc $PWD/dataplane/bpfc-dataplane-status"
KEEP=0; [ "$1" = "-k" ] && KEEP=1
require_root "dataplane-udp"
for t in ip ethtool ping nc nft cmp python3; do command -v $t >/dev/null || { test_skip "dataplane-udp (missing $t)"; exit 0; }; done
[ -x "$BPFC" ] || { echo "build bpfc first (make)"; exit 1; }
MP_A=$($GEN -i ua0 --map-prefix); MP_B=$($GEN -i ub0 --map-prefix)

MAPS=/run/bpfc-dpu-test
CONF=/tmp/bpfc-dpu-test
NSA=dpua; NSB=dpub; NSR=dpur
cleanup() {
    ip netns del $NSA 2>/dev/null; ip netns del $NSB 2>/dev/null; ip netns del $NSR 2>/dev/null
    umount $MAPS 2>/dev/null; rm -rf $MAPS $CONF
}
[ $KEEP -eq 0 ] && trap 'cleanup; rm -f "$TESTS_FAILED_FILE"' EXIT
cleanup
mkdir -p $MAPS $CONF && mount -t bpf bpf $MAPS || { echo "cannot mount bpffs"; exit 1; }
ulimit -l unlimited 2>/dev/null

A() { ip netns exec $NSA "$@"; }
B() { ip netns exec $NSB "$@"; }
R() { ip netns exec $NSR "$@"; }

for n in $NSA $NSB $NSR; do ip netns add $n; ip -n $n link set lo up; done
ip link add ua0 netns $NSA type veth peer name ur0 netns $NSR
ip link add ub0 netns $NSB type veth peer name ur1 netns $NSR
for x in "$NSA ua0 192.0.2.1/24" "$NSB ub0 100.64.0.2/24" "$NSR ur0 192.0.2.254/24" "$NSR ur1 100.64.0.1/24"; do
    set -- $x
    ip -n $1 addr add $3 dev $2
    ip -n $1 link set $2 up
    ip -n $1 link set dev $2 gso_max_segs 1
    ip netns exec $1 ethtool -K $2 tso off gso off gro off >/dev/null 2>&1
done
A ip addr add 10.1.0.1/32 dev lo
B ip addr add 10.2.0.1/32 dev lo
R sysctl -qw net.ipv4.ip_forward=1
# Strict reverse-path filtering everywhere (the distribution default in new
# namespaces varies: RHEL/CentOS 1, others 0). A and B send pings from their
# site address on lo: with arp_announce 2 their ARP requests carry the
# interface address, as the setup hints say (R would ignore an ARP request
# from 10.x, which fails its reverse-path check).
for n in $NSA $NSB $NSR; do ip netns exec $n sysctl -qw net.ipv4.conf.all.rp_filter=1; done
A sysctl -qw net.ipv4.conf.all.arp_announce=2
B sysctl -qw net.ipv4.conf.all.arp_announce=2
B ip route add default via 100.64.0.1
# the site prefixes, as the generator's --setup-hints say (MTU for carrier udp)
A ip route add 10.2.0.0/16 via 192.0.2.254 dev ua0 src 10.1.0.1 mtu lock 1464
B ip route add 10.1.0.0/16 via 100.64.0.1 dev ub0 src 10.2.0.1 mtu lock 1464
# carrier-grade NAT in front of B
R nft -f - <<'EOF'
table ip nat {
    chain post { type nat hook postrouting priority srcnat; oifname "ur0" ip saddr 100.64.0.0/24 masquerade; }
}
EOF

# install <ns> <if> [generator options]: generate and attach with bpfc
install() {
    local ns=$1 ifc=$2; shift 2
    rm -rf $CONF/$ns/$ifc; $GEN -i $ifc -m $MAPS --remove-maps >/dev/null
    ip netns exec $ns $GEN -i $ifc -o $CONF/$ns "$@" >$CONF/gen.log 2>&1 || { cat $CONF/gen.log; return 1; }
    ip netns exec $ns $BPFC -i $ifc -c 2>/dev/null
    local f
    for f in $CONF/$ns/$ifc/egress/*.bpfc $CONF/$ns/$ifc/ingress/*.bpfc; do
        ip netns exec $ns $BPFC -m $MAPS -i $ifc -d $(basename $(dirname $f)) -p $(basename $f .bpfc) -f $f >$CONF/load.log 2>&1 ||
            { echo "load $f failed:"; tail -5 $CONF/load.log; return 1; }
    done
}
# loss <ns> <if> <basis points>: random loss of the frames arriving on <if>
loss() {
    ip netns exec $1 $BPFC -m $MAPS -i $2 -d ingress -p 50 \
        "get map LOSS_$2 1 P; get random R; calc mod R 10000; if R lt %P; drop; end-if; continue" >/dev/null 2>&1
    $BPFC -m $MAPS -w LOSS_$2 1 $3 >/dev/null
}
# v <map> <key>: decimal value or 0
v() {
    local k=$(printf "0x%016x" $2)
    local x=$($BPFC -m $MAPS -r $1 2>/dev/null | awk -v k=$k '$3 == k {print $6}')
    [ -n "$x" ] && echo $((16#${x#0x})) || echo 0
}
ip_of() { echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"; }
# pings <ns> <src> <dst> <n>: replies received
pings() { ip netns exec $1 ping -c $4 -i 0.05 -W 1 -I $2 $3 2>/dev/null | awk '/received/ {print $4}'; }
# verify <from-ns> <to-ns> <dst> <port> <count> <pps> <size>: "delivered-permille corrupt"
verify() {
    ip netns exec $2 python3 -I tests/udp-verify.py recv $4 $(( $5 / $6 + 4 )) > $CONF/verify.txt &
    local rp=$!; sleep 0.5
    ip netns exec $1 python3 -I tests/udp-verify.py send $3 $4 $5 $6 $7
    wait $rp
    awk -v n=$5 '{printf "%d %d\n", $4 * 1000 / n, $6}' $CONF/verify.txt
}
if nc -h 2>&1 | grep -q -- '--send-only'; then NC_SEND="nc --send-only"; else NC_SEND="nc -N"; fi
# tcp_copy <port>: 2 MB from A (10.1.0.1) to B (10.2.0.1), compared
tcp_copy() {
    head -c 2000000 /dev/urandom > $CONF/src.bin; rm -f $CONF/dst.bin
    B timeout 60 nc -l -p $1 > $CONF/dst.bin & local rp=$!
    sleep 0.5
    A timeout 60 $NC_SEND -s 10.1.0.1 10.2.0.1 $1 < $CONF/src.bin
    wait $rp
    cmp -s $CONF/src.bin $CONF/dst.bin
}

# diag: what each end and R saw, when the first carrier check fails
diag() {
    local n k
    echo "    --- diagnostics (kernel $(uname -r), $(uname -m))"
    for n in A:${MP_A}:$NSA:ua0 B:${MP_B}:$NSB:ub0; do
        IFS=: read -r x mp ns ifc <<< "$n"
        printf "    %s tx:" "$x"; for k in 2 4 65 66 67 68; do printf " %s=%s" $k "$(v ${mp}_tx $k)"; done
        printf "  rx:"; for k in 2 93 94 95; do printf " %s=%s" $k "$(v ${mp}_rx $k)"; done; echo
        echo "    $x filters: $(ip netns exec $ns tc filter show dev $ifc ingress | grep -o 'pref [0-9]*' | sort -u | tr '\n' ' ')/ egress: $(ip netns exec $ns tc filter show dev $ifc egress | grep -o 'pref [0-9]*' | sort -u | tr '\n' ' ')"
    done
    if command -v tcpdump >/dev/null; then
        R timeout 3 tcpdump -lnni ur1 -c 4 udp > $CONF/d1.txt 2>/dev/null &
        R timeout 3 tcpdump -lnni ur0 -c 4 udp > $CONF/d0.txt 2>/dev/null &
        A timeout 3 tcpdump -lnni ua0 -c 4 udp > $CONF/da.txt 2>/dev/null &
        sleep 0.5; pings $NSB 10.2.0.1 10.1.0.1 2 >/dev/null; wait
        echo "    R from B (ur1):"; sed 's/^/      /' $CONF/d1.txt
        echo "    R to A (ur0):";   sed 's/^/      /' $CONF/d0.txt
        echo "    A (ua0):";        sed 's/^/      /' $CONF/da.txt
    fi
    echo "    R nat: $(R nft list ruleset 2>&1 | grep -c masquerade) masquerade rule(s); B neigh: $(B ip neigh show dev ub0 | head -2 | tr '\n' ';')"
    echo "    ---"
}

echo "generator: carrier settings"
gen_err() { local msg=$1; shift; local out; out=$($GEN -i ua0 -o - "$@" 2>&1 >/dev/null); [[ "$out" == *"$msg"* ]]; }
check "udp needs protect"                gen_err "needs protect" --carrier udp --peer 192.0.2.1 --local-address 192.0.2.9
check "udp needs a peer"                 gen_err "needs peer" --carrier udp --protect 10.2.0.0/16 --local-address 192.0.2.9
check "a bad prefix is refused"          gen_err "is not a prefix" --carrier udp --peer learn --protect 10.2.0.0/33 --local-address 192.0.2.9
check "a bad peer is refused"            gen_err "must be an IPv4 address" --carrier udp --peer 300.1.1.1 --protect 10.2.0.0/16
check "local-address auto needs an address" gen_err "has no IPv4 address" --carrier udp --peer learn --protect 10.2.0.0/16
check "low --priority refused"           gen_err "priority above 10" --carrier udp-inline --protect 10.2.0.0/16 -b 5
D=$CONF/gen; rm -rf $D
$GEN -i ua0 -o $D --carrier udp --peer 192.0.2.7 --protect 10.2.0.0/16 --local-address 192.0.2.9 >/dev/null
check "udp: carrier programs at ingress 90 and egress 140" eval '[ -f $D/ua0/ingress/90.bpfc ] && [ -f $D/ua0/egress/140.bpfc ]'
check "udp: packets up to 1464 bytes protected" grep -q "if FLEN gt 1478;" $D/ua0/egress/100.bpfc
$GEN -i ua0 -o $D >/dev/null
check "back to ethernet removes the carrier programs" eval '[ ! -e $D/ua0/ingress/90.bpfc ] && [ ! -e $D/ua0/egress/140.bpfc ] && grep -q "if FLEN gt 1506;" $D/ua0/egress/100.bpfc'
check "hints give the route MTU per prefix" eval '$GEN -i ua0 --setup-hints --carrier udp-inline --protect 10.2.0.0/16,10.3.0.0/16 | grep -c "mtu lock 1464" | grep -qx 2'

echo "carrier udp: B behind NAT, A learns it"
install $NSA ua0 --carrier udp --peer learn --protect 10.2.0.0/16 || test_fail "install A"
install $NSB ub0 --carrier udp --peer 192.0.2.1 --protect 10.1.0.0/16 || test_fail "install B"
check "A has not learned a peer yet"        [ "$(v ${MP_A}_tx 60)" -eq 0 ]
n=$(pings $NSB 10.2.0.1 10.1.0.1 20)
check "B -> A through the carrier (10.x is not routed by R)" [ "$n" -ge 19 ]
[ "$n" -ge 19 ] || diag
PA=$(v ${MP_A}_tx 60); PP=$(v ${MP_A}_tx 61)
check "A learned the NAT address ($(ip_of $PA):$PP)" [ "$(ip_of $PA)" = 192.0.2.254 -a "$PP" -gt 0 ]
check "A's local address: the one B's packets come to" [ "$(ip_of $(v ${MP_A}_tx 62))" = 192.0.2.1 ]
check "A -> B through the carrier"          [ "$(pings $NSA 10.1.0.1 10.2.0.1 20)" -ge 19 ]
check "both ends received carrier frames"   [ "$(v ${MP_A}_rx 93)" -gt 0 -a "$(v ${MP_B}_rx 93)" -gt 0 ]
check "reports arrive (peer measures us)"   eval '[ "$(v ${MP_A}_tx 19)" -gt 0 ] || { pings $NSA 10.1.0.1 10.2.0.1 30 >/dev/null; [ "$(v ${MP_A}_tx 19)" -gt 0 ]; }'
b65=$(v ${MP_A}_tx 65); n2=$(v ${MP_A}_tx 2)
check "other traffic is left alone (A -> R)" [ "$(pings $NSA 192.0.2.1 192.0.2.254 10)" -ge 9 ]
check "...not sequenced, not counted"       [ "$(v ${MP_A}_tx 2)" -eq "$n2" -a "$(v ${MP_A}_tx 65)" -eq "$b65" ]
R nft add table ip t; R nft add chain ip t f "{ type filter hook forward priority 0; }"
R nft add rule ip t f ip daddr 10.0.0.0/8 counter
R nft add rule ip t f udp dport 47810 counter
pings $NSA 10.1.0.1 10.2.0.1 10 >/dev/null
check "R only sees UDP port 47810, never the site addresses" eval \
    'R nft list chain ip t f | grep "daddr 10.0.0.0/8" | grep -q "packets 0 " && R nft list chain ip t f | grep "dport 47810" | grep -vq "packets 0 "'
R nft delete table ip t
rej=$(v ${MP_B}_rx 94)
R sh -c 'printf "garbage-garbage-garbage" | nc -u -w1 -p 47810 100.64.0.2 47810' 2>/dev/null
check "B drops carrier packets that are not from its peer" eval '[ "$(v ${MP_B}_rx 94)" -gt "$rej" ]'

loss $NSA ua0 500; loss $NSB ub0 500
read del bad < <(verify $NSB $NSA 10.1.0.1 6001 4000 1000 1200)
check "5 % loss each way: UDP B -> A delivered $del permille, $bad corrupt" [ "$del" -ge 985 -a "$bad" -eq 0 ]
check "...repaired by FEC or ARQ"           [ $(( $(v ${MP_A}_rx 6) + $(v ${MP_A}_rx 7) )) -gt 0 ]
check "5 % loss each way: 2 MB TCP A -> B intact" tcp_copy 5201
$BPFC -m $MAPS -w ${MP_A}_cfg 14 1 >/dev/null; $BPFC -m $MAPS -w ${MP_B}_cfg 14 1 >/dev/null
r7=$(v ${MP_B}_rx 7)
read del bad < <(verify $NSA $NSB 10.2.0.1 6002 2000 500 1200)
check "FEC off, ARQ only: A -> B delivered $del permille, $bad corrupt" [ "$del" -ge 985 -a "$bad" -eq 0 ]
check "...retransmissions came through the carrier" [ "$(v ${MP_B}_rx 7)" -gt "$r7" ]
$BPFC -m $MAPS -w ${MP_A}_cfg 14 0 >/dev/null; $BPFC -m $MAPS -w ${MP_B}_cfg 14 0 >/dev/null
loss $NSA ua0 0; loss $NSB ub0 0
A ip route change 10.2.0.0/16 via 192.0.2.254 dev ua0 src 10.1.0.1 mtu lock 1500
check "packets over 1464 bytes go out unprotected" eval \
    'b=$(v ${MP_A}_tx 4); A ping -c 1 -W 1 -M do -s 1440 -I 10.1.0.1 10.2.0.1 >/dev/null 2>&1; [ "$(v ${MP_A}_tx 4)" -gt "$b" ]'
A ip route change 10.2.0.0/16 via 192.0.2.254 dev ua0 src 10.1.0.1 mtu lock 1464
check "status shows the carrier and the learned peer" eval \
    'A $STATUS -m $MAPS -c $CONF/$NSA ua0 detail | grep -E "Carrier +udp" | grep -q "192.0.2.254"'
check "status JSON has the carrier" eval \
    'A $STATUS -m $MAPS -c $CONF/$NSA json | grep -q "\"carrier\": \"udp\""'
check "status set/unset peer (runtime override)" eval \
    'A $STATUS -m $MAPS -c $CONF/$NSA set ua0 peer 192.0.2.254:47810 >/dev/null && [ "$(ip_of $(v ${MP_A}_cfg 19))" = 192.0.2.254 ] &&
     A $STATUS -m $MAPS -c $CONF/$NSA ua0 detail | grep -q "192.0.2.254:47810 (set" &&
     A $STATUS -m $MAPS -c $CONF/$NSA unset ua0 peer >/dev/null && [ "$(v ${MP_A}_cfg 19)" -eq 0 ]'
# NAT mappings expire when idle (a CGNAT's after a minute or two): R's UDP
# timeouts are 2 s from here on.
R sysctl -qw net.netfilter.nf_conntrack_udp_timeout=2 net.netfilter.nf_conntrack_udp_timeout_stream=2
$BPFC -m $MAPS -w ${MP_B}_cfg 22 86400000 >/dev/null     # keepalive off on B
pings $NSB 10.2.0.1 10.1.0.1 2 >/dev/null; sleep 3
check "idle, no keepalive: the mapping expired, A cannot reach B" [ "$(pings $NSA 10.1.0.1 10.2.0.1 3)" -eq 0 ]
ka=$(v ${MP_B}_tx 68)
B $STATUS -m $MAPS -c $CONF/$NSB set ub0 keepalive 1s >/dev/null   # keepalive every second
B ping -c 40 -i 0.2 -I 100.64.0.2 100.64.0.1 >/dev/null 2>&1 & BG=$!
sleep 3
check "keepalive rides on B's other traffic: A reaches B again" [ "$(pings $NSA 10.1.0.1 10.2.0.1 10)" -ge 9 ]
check "...keepalives sent and dropped by A" [ "$(v ${MP_B}_tx 68)" -gt "$ka" -a "$(v ${MP_A}_rx 95)" -gt 0 ]
check "...status shows them" eval 'B $STATUS -m $MAPS -c $CONF/$NSB ub0 detail | grep -Eq "keepalive 1.0 s \([1-9][0-9]* sent"'
wait $BG
$BPFC -m $MAPS -w ${MP_B}_cfg 22 86400000 >/dev/null
# The NAT moves B to another port: A follows.
R nft flush ruleset
R nft -f - <<'EOF'
table ip nat {
    chain post { type nat hook postrouting priority srcnat; oifname "ur0" ip saddr 100.64.0.0/24 meta l4proto udp masquerade to :40000-40010; }
}
EOF
sleep 3
pings $NSB 10.2.0.1 10.1.0.1 3 >/dev/null
check "a new NAT mapping is followed (port $(v ${MP_A}_tx 61), $(v ${MP_A}_tx 66) changes)" eval \
    '[ "$(ip_of $(v ${MP_A}_tx 60))" = 192.0.2.254 ] && [ "$(v ${MP_A}_tx 61)" -ge 40000 ] && [ "$(v ${MP_A}_tx 61)" -le 40010 ] && [ "$(pings $NSA 10.1.0.1 10.2.0.1 10)" -ge 9 ]'

echo "carrier udp-inline: a private routed WAN"
R nft flush ruleset
R ip route add 10.1.0.0/16 via 192.0.2.1
R ip route add 10.2.0.0/16 via 100.64.0.2
A ip route change 10.2.0.0/16 via 192.0.2.254 dev ua0 src 10.1.0.1 mtu lock 1464
B ip route change 10.1.0.0/16 via 100.64.0.1 dev ub0 src 10.2.0.1 mtu lock 1464
install $NSA ua0 --carrier udp-inline --protect 10.2.0.0/16 || test_fail "install A inline"
install $NSB ub0 --carrier udp-inline --protect 10.1.0.0/16 || test_fail "install B inline"
check "A -> B and back"                      [ "$(pings $NSA 10.1.0.1 10.2.0.1 20)" -ge 19 ]
R nft add table ip t; R nft add chain ip t f "{ type filter hook forward priority 0; }"
R nft add rule ip t f ip saddr 10.1.0.1 ip daddr 10.2.0.1 udp dport 47810 counter
R nft add rule ip t f ip saddr 10.1.0.1 ip daddr 10.2.0.1 ip protocol icmp counter
R nft add rule ip t f ip saddr 10.1.0.1 ip daddr 10.2.0.1 ip dscp ef udp sport 46337 counter
B nft add table ip t; B nft add chain ip t i "{ type filter hook input priority 0; }"
B nft add rule ip t i ip saddr 10.1.0.1 ip dscp ef ip ttl 63 icmp type echo-request counter
B nft add rule ip t i ip saddr 10.1.0.1 ip dscp cs1 icmp type echo-request counter
A ping -c 10 -i 0.05 -W 1 -Q 0xb8 -I 10.1.0.1 10.2.0.1 >/dev/null 2>&1
check "R sees UDP between the site addresses, not ICMP" eval \
    'R nft list chain ip t f | grep "dport 47810" | grep -vq "packets 0 " && R nft list chain ip t f | grep "protocol icmp" | grep -q "packets 0 "'
check "...with the packet's DSCP (EF) and the protocol in the source port" eval \
    'R nft list chain ip t f | grep "dscp ef" | grep -q "packets 10 "'
check "B delivers it as it arrived: DSCP EF, TTL lowered by R" eval \
    'B nft list chain ip t i | grep "dscp ef" | grep -q "packets 10 "'
check "16 bytes per data packet: IP packets up to 1464 protected" grep -q "if FLEN gt 1478;" $CONF/$NSA/ua0/egress/100.bpfc
# The WAN remarks DSCP to CS1 and drops 5 %: B delivers CS1, and FEC still
# rebuilds (TOS and TTL are left out of the parity).
R nft add chain ip t m "{ type filter hook forward priority -150; }"
R nft add rule ip t m ip saddr 10.1.0.0/16 ip dscp set cs1
R nft add rule ip t m ip saddr 10.2.0.0/16 ip dscp set cs1
A ping -c 5 -i 0.05 -W 1 -Q 0xb8 -I 10.1.0.1 10.2.0.1 >/dev/null 2>&1
check "the WAN remarks to CS1: B delivers CS1" eval 'B nft list chain ip t i | grep "dscp cs1" | grep -q "packets 5 "'
B nft delete table ip t
loss $NSA ua0 500; loss $NSB ub0 500
r6=$(v ${MP_A}_rx 6)
read del bad < <(verify $NSB $NSA 10.1.0.1 6003 4000 1000 1200)
check "5 % loss each way, remarked: UDP B -> A delivered $del permille, $bad corrupt" [ "$del" -ge 985 -a "$bad" -eq 0 ]
check "...FEC rebuilt packets, none failed checks" [ "$(v ${MP_A}_rx 6)" -gt "$r6" -a "$(v ${MP_A}_rx 34)" -eq 0 ]
check "5 % loss each way: 2 MB TCP A -> B intact" tcp_copy 5202
loss $NSA ua0 0; loss $NSB ub0 0
R nft delete table ip t
check "status shows the inline carrier" eval 'A $STATUS -m $MAPS -c $CONF/$NSA ua0 detail | grep -Eq "Carrier +udp-inline"'

tests_exit
