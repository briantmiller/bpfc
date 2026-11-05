#!/bin/bash
# End-to-end tests for the FEC / INT / ARQ dataplane and the bpfc helpers it
# uses. Two network namespaces joined by veth pairs; loss is added by a small
# bpfc program on the receiving side's ingress, ahead of the dataplane, so it
# looks like loss on the wire (netem is not needed).
#
#   sudo bash tests/test-dataplane.sh [-k]      (-k: keep namespaces afterwards)
#
# A middle namespace running tests/link-emulator.py adds 400 ms each way for
# the satellite (geo profile) tests; tests/udp-verify.py checks that every
# delivered datagram arrives with its exact contents.
#
# Needs: ip, ethtool, ping, nc, iperf3, cmp, python3.

cd "$(dirname "$0")/.." || exit 1
BPFC=$PWD/bpfc
GEN=$PWD/dataplane/bpfc-dataplane-gen
# map prefix of each test interface (dp + hash of the name, see the generator)
for i in dpa0 dpa1 dpb0 dpb1 dps0 dps1; do declare "MP_$i=$($GEN -i $i --map-prefix)"; done
STATUS="env BPFC=$PWD/bpfc $PWD/dataplane/bpfc-dataplane-status"
KEEP=0; [ "$1" = "-k" ] && KEEP=1

RED='\e[31m'; GREEN='\e[32m'; NC='\e[0m'
PASSES=0; FAILS=0
pass() { echo -e "$* ${GREEN}PASS${NC}"; PASSES=$((PASSES + 1)); }
fail() { echo -e "$* ${RED}FAIL${NC}"; FAILS=$((FAILS + 1)); }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }

[ "$(id -u)" -eq 0 ] || { echo "Must be run as root"; exit 1; }
for t in ip ethtool ping nc iperf3 cmp python3; do command -v $t >/dev/null || { echo "missing $t"; exit 1; }; done
[ -x "$BPFC" ] || { echo "build bpfc first (make)"; exit 1; }

MAPS=/run/bpfc-dp-test
CONF=/tmp/bpfc-dp-test
NSA=dpta; NSB=dptb; NSM=dptm
EMU_PID=""
cleanup() {
    [ -n "$EMU_PID" ] && kill $EMU_PID 2>/dev/null
    pkill -f "iperf3 -s -p 520" 2>/dev/null
    ip netns del $NSA 2>/dev/null; ip netns del $NSB 2>/dev/null; ip netns del $NSM 2>/dev/null
    umount $MAPS 2>/dev/null; rm -rf $MAPS $CONF
}
[ $KEEP -eq 0 ] && trap cleanup EXIT
cleanup
mkdir -p $MAPS $CONF && mount -t bpf bpf $MAPS || { echo "cannot mount bpffs"; exit 1; }

A() { ip netns exec $NSA "$@"; }
B() { ip netns exec $NSB "$@"; }

# setup <ns> <if> <address>: as the generator's --setup-hints say
setup() {
    ip -n $1 link set $2 up
    ip -n $1 addr add $3/24 dev $2
    ip -n $1 link set dev $2 gso_max_segs 1
    ip netns exec $1 ethtool -K $2 tso off gso off gro off >/dev/null 2>&1
    ip -n $1 route replace ${3%.*}.0/24 dev $2 proto kernel scope link src $3 mtu lock 1492
}
# link <a-if> <b-if> <x>: veth pair, 10.77.x.1 <-> 10.77.x.2
link() {
    ip link add $1 netns $NSA type veth peer name $2 netns $NSB
    setup $NSA $1 10.77.$3.1
    setup $NSB $2 10.77.$3.2
}
ip netns add $NSA; ip netns add $NSB
ip -n $NSA link set lo up; ip -n $NSB link set lo up
link dpa0 dpb0 0
link dpa1 dpb1 1

# install <ns> <if> [generator options]: generate and attach with bpfc
install() {
    local ns=$1 ifc=$2; shift 2
    rm -rf $CONF/$ns/$ifc; $GEN -i $ifc -m $MAPS --remove-maps >/dev/null
    $GEN -i $ifc -o $CONF/$ns "$@" >/dev/null || return 1
    ip netns exec $ns $BPFC -i $ifc -c 2>/dev/null
    local f
    for f in $CONF/$ns/$ifc/egress/*.bpfc $CONF/$ns/$ifc/ingress/*.bpfc; do
        ip netns exec $ns $BPFC -m $MAPS -i $ifc -d $(basename $(dirname $f)) -p $(basename $f .bpfc) -f $f >/dev/null 2>&1 || return 1
    done
}
# loss <ns> <if> <basis points>: random loss of the frames <if> sends. The
# frames are dropped on arrival at the peer, ahead of its dataplane: a drop on
# the sender's own egress is reported back to the sending socket, and TCP then
# treats the segment as never sent although FEC can still rebuild it at the
# peer (the peer acknowledges data the sender thinks is unsent, which can
# stall the connection; real loss on the wire never does that).
loss() {
    local ns=$NSB peer
    case $2 in
        dpa*) peer=dpb${2#dpa} ;;
        dpb*) peer=dpa${2#dpb}; ns=$NSA ;;
        dps0) peer=dps1 ;;
        dps1) peer=dps0; ns=$NSA ;;
        *) echo "loss: unknown interface $2"; return 1 ;;
    esac
    ip netns exec $ns $BPFC -m $MAPS -i $peer -d ingress -p 50 \
        "get map LOSS_$2 1 P; get random R; calc mod R 10000; if R lt %P; drop; end-if; continue" >/dev/null 2>&1
    $BPFC -m $MAPS -w LOSS_$2 1 $3 >/dev/null
}
# v <map> <key>: decimal value or 0
v() {
    local k=$(printf "0x%016x" $2)
    local x=$($BPFC -m $MAPS -r $1 2>/dev/null | awk -v k=$k '$3 == k {print $6}')
    [ -n "$x" ] && echo $((16#${x#0x})) || echo 0
}
udp() {   # udp <ns> <dst> <port> <rate> <seconds>: iperf3 lost percentage (integer x100)
    ip netns exec $NSB iperf3 -s -p $3 -1 -D >/dev/null 2>&1; sleep 0.5
    ip netns exec $1 iperf3 -c $2 -p $3 -u -b $4 -l 1400 -t $5 2>/dev/null | awk '/receiver/{gsub(/[()%]/,"",$NF); printf "%d\n", $NF*100}'
}
# verify <ns> <dst> <port> <count> <pps> <size> <loss-ns> <loss-if> <loss bp>:
# send datagrams with checked contents; prints "delivered-permille corrupt"
verify() {
    ip netns exec $NSB python3 -I tests/udp-verify.py recv $3 $(( $4 / $5 + 6 )) > $CONF/verify.txt &
    local rp=$!; sleep 0.5
    ip netns exec $1 python3 -I tests/udp-verify.py send $2 $3 $4 $5 $6
    wait $rp
    awk -v n=$4 '{printf "%d %d\n", $4 * 1000 / n, $6}' $CONF/verify.txt
}
# nc that closes its side at end of input: OpenBSD nc needs -N, ncat
# (RHEL) uses --send-only.
if nc -h 2>&1 | grep -q -- '--send-only'; then NC_SEND="nc --send-only"; else NC_SEND="nc -N"; fi
# tcp_copy <port> <dst> <src file> <dst file> <timeout>: A sends to B; waits
# until the receiver has written everything (not a fixed sleep)
tcp_copy() {
    rm -f "$4"
    ip netns exec $NSB timeout $5 nc -l -p $1 > "$4" & local rp=$!
    sleep 0.5
    ip netns exec $NSA timeout $5 $NC_SEND $2 $1 < "$3"
    wait $rp
}
# cap_expected <rx map>: the capacity estimate the probe samples (60-75) and
# their count (43) call for: of the largest, the 1st with up to 4 samples, the
# 2nd with up to 8, the 3rd with up to 12, else the 4th
cap_expected() {
    local n k
    n=$(v $1 43)
    [ "$n" -eq 0 ] && { echo 0; return; }
    k=4; [ "$n" -le 12 ] && k=3; [ "$n" -le 8 ] && k=2; [ "$n" -le 4 ] && k=1
    for i in $(seq 60 75); do v $1 $i; done | sort -rn | sed -n "${k}p"
}
csum_errors() {
    ip netns exec $1 awk '/^Tcp:/{if(!h){split($0,n);h=1}else{split($0,v);for(i in n)if(n[i]=="InCsumErrors")print v[i]}}' /proc/net/snmp
}

echo "== profiles"
PD=$CONF/profiles; mkdir -p $PD
cat > $PD/ship.profile <<'EOF'
description = test profile   # comment
inherit = geo
link-rate = 8m
rtt = 620ms
EOF
printf 'inherit = geo\nfec-kk = 3\n' > $PD/bad.profile
printf 'inherit = loop2\n' > $PD/loop1.profile; printf 'inherit = loop1\n' > $PD/loop2.profile
check "built-in profiles listed" sh -c "$GEN --list-profiles | grep -q '^direct ' && $GEN --list-profiles | grep -q '^wan ' && $GEN --list-profiles | grep -q '^geo '"
check "geo sizes the ARQ ring from rate x RTT (3000)" sh -c "$GEN --show-profile geo | grep -q 'ARQ ring *3000 packets'"
check "inheritance, command line wins" sh -c "$GEN --profile-dir $PD --show-profile ship --fec-k-min 5 | grep -q '^fec-k-min *= 5 .*command line' && $GEN --profile-dir $PD --show-profile ship | grep -q '^fec-floor *= 15 .*profile geo' && $GEN --profile-dir $PD --show-profile ship | grep -q 'ARQ ring *930 packets'"
check "unknown setting in a profile is an error" sh -c "! $GEN --profile-dir $PD --show-profile bad 2>&1 >/dev/null && $GEN --profile-dir $PD --show-profile bad 2>&1 | grep -q 'bad.profile:2: unknown setting'"
check "inheritance loop is an error" sh -c "$GEN --profile-dir $PD --show-profile loop1 2>&1 | grep -q 'loop: loop1 -> loop2 -> loop1'"
check "invalid value is an error" sh -c "$GEN --show-profile geo --fec-k 20 2>&1 | grep -q 'fec-k = 20 (from command line): must be 1-15'"
$GEN --profile-dir $PD --save-profile ship2 --profile ship --rtt 700ms >/dev/null
check "save-profile round trip" sh -c "grep -q '^inherit = ship' $PD/ship2.profile && $GEN --profile-dir $PD --show-profile ship2 | grep -q '^rtt *= 700ms *# profile ship2'"
check "plain numbers keep their old units" sh -c "$GEN -i x0 -o - --fec-cooldown 5 --report-interval 750 | grep -q 'cooldown_ms=5000 .*report_ms=750'"
check "leo profile: 3 s probes, no backoff, 20 ms trains, median of 15 s" sh -c "$GEN --list-profiles | grep -q '^leo ' && $GEN -i x0 -o - --profile leo | grep -q 'probe_ms=3000 backoff=1 .*cap_window_ms=15000 train_ms=20 train_max=256 train_skip=10 cap_pct=50'"
check "probe-train: pairs by default, checked" sh -c "$GEN -i x0 -o - | grep -q 'train_ms=0 ' && $GEN -i x0 -o - --probe-train 1ms 2>&1 | grep -q 'probe-train must be'"
check "capacity-window: off by default, checked" sh -c "$GEN -i x0 -o - | grep -q 'cap_window_ms=0' && $GEN -i x0 -o - --capacity-window 50ms 2>&1 | grep -q 'capacity-window must be'"

echo "== bpfc helpers"
A $BPFC -m $MAPS -i dpa0 -d egress -p 100 'match ip; insert-l2 8 0x88B5; set bytes 14 8 0x0102030405060708; continue' >/dev/null
B $BPFC -m $MAPS -i dpb0 -d ingress -p 100 'match eth-proto 0x88B5; get bytes 14 8 S; decl T 8; set val T 0x0102030405060708; if S eq %T; strip-l2 8 0x0800; accept; end-if; drop' >/dev/null
B $BPFC -m $MAPS -i dpb0 -d egress -p 100 'match ip; insert-l2 8 0x88B5; continue' >/dev/null
A $BPFC -m $MAPS -i dpa0 -d ingress -p 100 'match eth-proto 0x88B5; strip-l2 8 0x0800; accept' >/dev/null
check "insert-l2 / strip-l2 (ping, 1492-byte IP)" A ping -c 2 -W 1 -s 1464 -M do -q 10.77.0.2
head -c 3000000 /dev/urandom > $CONF/tx.bin
tcp_copy 5001 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "insert-l2 / strip-l2 (TCP 3 MB intact)" cmp -s $CONF/tx.bin $CONF/rx.bin
A $BPFC -i dpa0 -c; B $BPFC -i dpb0 -c

A $BPFC -m $MAPS -i dpa0 -d egress -p 100 'shared-buffer-map XB 2 3008; match ip; get ip-len L; zero-buffer-keyed XB 1 1504; xor-packet-keyed XB 1 %L 14 0; set bytes 14 4 0; set bytes 30 4 0; load-packet-keyed XB 1 %L 0 14; continue' >/dev/null
ok=1; for s in 1 7 9 63 65 127 255 257 1000 1464; do A ping -c 1 -W 1 -s $s -q 10.77.0.2 >/dev/null || ok=0; done
check "xor-packet-keyed / zero-buffer-keyed round trip (10 sizes)" [ $ok -eq 1 ]
A $BPFC -i dpa0 -c
A ethtool -K dpa0 tx off >/dev/null
# only this copy's segments (port 5005): a late packet of an earlier
# connection may still carry an offloaded, unfinished checksum
B $BPFC -m $MAPS -i dpb0 -d ingress -p 100 'match tcp; match tcp-dst 5005; calc-csum tcp V; get bytes 50 2 F; if V ne %F; calc-map add CSUMT 1 1; end-if; calc-map add CSUMT 2 1; set bytes 50 2 0x1234; recalc-tcp-csum; continue' >/dev/null
tcp_copy 5005 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "calc-csum tcp matches every segment ($(v CSUMT 1) of $(v CSUMT 2) differ)" [ "$(v CSUMT 1)" -eq 0 -a "$(v CSUMT 2)" -gt 100 ]
check "recalc-tcp-csum repairs every segment" cmp -s $CONF/tx.bin $CONF/rx.bin
check "calc-map add counts atomically" [ "$(v CSUMT 2)" -gt 2000 ]
B $BPFC -i dpb0 -c; A ethtool -K dpa0 tx on >/dev/null
$BPFC -m $MAPS -w CSUMT 9 0x123456789 >/dev/null
check "bpfc -w writes a 64-bit value" [ "$(v CSUMT 9)" -eq $((0x123456789)) ]

echo "== bpfc TCP helpers"
# On egress, locally sent TCP still has its checksum completion pending (it
# is finished after the program, over the bytes as rewritten), so these
# rewrites do not recompute it; forwarded packets would need recalc-tcp-csum.
# B ingress, A -> B port 5010: header fields, options, payload, sequence, flow keys
B $BPFC -m $MAPS -i dpb0 -d ingress -p 100 'match tcp; match tcp-dst 5010;
  get tcp-flags F; decl S 8; set val S %F; calc and S 0x02;
  if S ne 0;
    get tcp-hlen H; set map TT 1 %H; free H;
    tcp-option 2 O L; set map TT 2 %L; decl P 8; set val P %O; calc add P 2; get bytes %P 2 M; set map TT 3 %M;
    free M; free P; free L; free O;
    tcp-option 8 O L; set map TT 4 %L; free L; free O;
    tcp-option 99 O; set map TT 5 %O; free O;
    get tcp-seq Q; calc add Q 1; set map TT 6 %Q; set map TT 7 %Q; free Q;
    set map TT 8 %F;
  end-if;
  free S; free F;
  get payload-len PL;
  if PL gt 0;
    calc-map add TT 9 %PL;
    get tcp-seq Q; calc add Q %PL; get map TT 7 MX;
    if Q seq-gt %MX; set map TT 7 %Q; end-if;
    get flow-key K; set map TT 11 %K; get flow-key K symmetric; set map TT 12 %K;
  end-if;
  continue' >/dev/null || echo "    (B ingress program failed to load)"
# A ingress, B -> A: the same flow seen from the other side, and the ACKs
A $BPFC -m $MAPS -i dpa0 -d ingress -p 100 'match tcp; match tcp-src 5010;
  get flow-key K reverse; set map TT 13 %K; get flow-key K symmetric; set map TT 14 %K;
  get tcp-ack AK; get map TT 15 MX; if MX eq 0; set map TT 15 %AK; end-if; if AK seq-gt %MX; set map TT 15 %AK; end-if;
  continue' >/dev/null || echo "    (A ingress program failed to load)"
head -c 3000000 /dev/urandom > $CONF/tx.bin
tcp_copy 5010 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "tcp-flags, tcp-hlen on the SYN (flags $(v TT 8), header $(v TT 1) bytes)" [ "$(v TT 8)" -eq 2 -a "$(v TT 1)" -ge 24 -a "$(v TT 1)" -le 60 ]
check "tcp-option finds MSS ($(v TT 3), length $(v TT 2)) and timestamps (length $(v TT 4)), not kind 99" [ "$(v TT 2)" -eq 4 -a "$(v TT 3)" -ge 536 -a "$(v TT 3)" -le 1460 -a "$(v TT 4)" -eq 10 -a "$(v TT 5)" -eq 0 ]
check "payload-len adds up to at least the 3 MB sent ($(v TT 9), with retransmissions)" [ "$(v TT 9)" -ge 3000000 -a "$(v TT 9)" -le 3300000 ]
check "tcp-seq + seq-gt: highest sequence - ISN = 3 MB ($(( ($(v TT 7) - $(v TT 6) + 4294967296) % 4294967296 )))" [ $(( ($(v TT 7) - $(v TT 6) + 4294967296) % 4294967296 )) -eq 3000000 ]
check "tcp-ack: the receiver acknowledged it all, and the FIN" [ $(( ($(v TT 15) - $(v TT 6) + 4294967296) % 4294967296 )) -eq 3000001 ]
check "flow-key: reverse on the return path equals the forward key, symmetric the same both ways" [ "$(v TT 11)" != 0 -a "$(v TT 11)" = "$(v TT 13)" -a "$(v TT 12)" = "$(v TT 14)" ]
A $BPFC -i dpa0 -c; B $BPFC -i dpb0 -c
# B egress: lower the MSS B announces to 1000 (set bytes at a variable offset)
B $BPFC -m $MAPS -i dpb0 -d egress -p 100 'match tcp; match tcp-src 5011;
  get tcp-flags F; calc and F 0x12;
  if F eq 0x12; tcp-option 2 O L; if L eq 4; decl P 8; set val P %O; calc add P 2; set bytes %P 2 1000; end-if; end-if;
  continue' >/dev/null
B $BPFC -m $MAPS -i dpb0 -d ingress -p 100 'match tcp; match tcp-dst 5011; get payload-len PL; get map TT 20 MX; if PL gt %MX; set map TT 20 %PL; end-if; continue' >/dev/null
tcp_copy 5011 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "set bytes %VAR rewrote the MSS: largest segment $(v TT 20) bytes, data intact" sh -c "[ $(v TT 20) -le 1000 -a $(v TT 20) -ge 900 ] && cmp -s $CONF/tx.bin $CONF/rx.bin"
B $BPFC -i dpb0 -c
# A egress: blank the timestamp option with NOPs (fill-bytes at a variable offset and length)
A $BPFC -m $MAPS -i dpa0 -d egress -p 100 'match tcp; match tcp-dst 5012; tcp-option 8 O L; if O gt 0; fill-bytes %O %L 1; end-if; continue' >/dev/null
B $BPFC -m $MAPS -i dpb0 -d ingress -p 100 'match tcp; match tcp-dst 5012; calc-map add TT 22 1; tcp-option 8 O L; if O gt 0; calc-map add TT 21 1; end-if; continue' >/dev/null
tcp_copy 5012 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "fill-bytes removed the timestamp option from all $(v TT 22) segments, data intact" sh -c "[ $(v TT 21) -eq 0 -a $(v TT 22) -gt 100 ] && cmp -s $CONF/tx.bin $CONF/rx.bin"
A $BPFC -i dpa0 -c; B $BPFC -i dpb0 -c
# skb->tstamp round trip and 64-bit seq compare across the wrap
A $BPFC -m $MAPS -i dpa0 -d egress -p 100 'match icmp; get time T; set tstamp %T; get tstamp X; if X eq %T; calc-map add TT 30 1; end-if;
  decl W 8; set val W 0xFFFFFFF0; decl Z 8; set val Z 0x10; if Z seq-gt %W; calc-map add TT 31 1; end-if; if W seq-lt %Z; calc-map add TT 32 1; end-if; if W seq-gt %Z; calc-map add TT 33 1; end-if;
  continue' >/dev/null
A ping -c 3 -i 0.2 -q 10.77.0.2 >/dev/null
check "set / get tstamp, seq-gt / seq-lt across the 32-bit wrap" [ "$(v TT 30)" -eq 3 -a "$(v TT 31)" -eq 3 -a "$(v TT 32)" -eq 3 -a "$(v TT 33)" -eq 0 ]
A $BPFC -i dpa0 -c

echo "== map names"
check "default prefix is dp + 8 base32 characters" sh -c "$GEN -i dpa0 --map-prefix | grep -Eq '^dp[a-z2-7]{8}\$'"
check "same interface, same prefix; others differ" [ "$($GEN -i dpa0 --map-prefix)" = "$MP_dpa0" -a "$MP_dpa0" != "$MP_dpb0" ]
check "any name the kernel allows (#, ;, +, 15 bytes)" sh -c "$GEN -i 'a#b;c+d' -o - | grep -q '^# dataplane: version=3 iface=a%23b%3Bc+d prefix=dp' && $GEN -i abcdefghijklmno --map-prefix >/dev/null"
check "':', '%', whitespace, '/' and 16 bytes refused" sh -c "! $GEN -i eth0:1 --map-prefix 2>/dev/null && ! $GEN -i 'e%d' --map-prefix 2>/dev/null && ! $GEN -i 'a b' --map-prefix 2>/dev/null && ! $GEN -i a/b --map-prefix 2>/dev/null && ! $GEN -i abcdefghijklmnop --map-prefix 2>/dev/null"
check "--prefix limited to 10 characters" sh -c "$GEN -i x0 -P sat1 --map-prefix | grep -qx sat1 && ! $GEN -i x0 -P abcdefghijk --map-prefix 2>/dev/null"
rm -rf $CONF/names; $GEN -i x0 -o $CONF/names >/dev/null
check "a prefix used by another interface is refused" sh -c "! $GEN -i x1 -P $($GEN -i x0 --map-prefix) -o $CONF/names 2>/dev/null && $GEN -i x0 -o $CONF/names >/dev/null"
MPX=$($GEN -i x9 --map-prefix)
A $BPFC -m $MAPS -i lo -d egress -p 300 "calc-map add ${MPX}_tx 1 1; calc-map add dp_x9_rx 1 1; calc-map add dp_x99_tx 1 1; continue" >/dev/null
A ping -c 1 -W 1 -q 127.0.0.1 >/dev/null; A $BPFC -i lo -c
$GEN -i x9 -m $MAPS --remove-maps >/dev/null
check "--remove-maps removes that interface's maps only (v3 and v2 names)" [ ! -e $MAPS/${MPX}_tx -a ! -e $MAPS/dp_x9_rx -a -e $MAPS/dp_x99_tx ]
rm -f $MAPS/dp_x99_tx
check "bpfc refuses a map name over 31 characters" sh -c "! ip netns exec $NSA $BPFC -m $MAPS -i lo -d egress -p 300 'calc-map add M2345678901234567890123456789012 1 1; continue' >/dev/null 2>&1"
A $BPFC -i lo -c 2>/dev/null

echo "== dataplane: clean link"
install $NSA dpa0 && install $NSB dpb0
check "generated programs load (6 per side)" [ "$(A tc filter show dev dpa0 ingress | grep -c 'bpf.*jited') $(A tc filter show dev dpa0 egress | grep -c 'bpf.*jited')" = "4 2" ]
check "ping through the dataplane" A ping -c 3 -W 1 -q 10.77.0.2
tcp_copy 5001 10.77.0.2 $CONF/tx.bin $CONF/rx.bin 30
check "TCP 3 MB intact" cmp -s $CONF/tx.bin $CONF/rx.bin
check "receiver saw every sequence number" [ "$(v ${MP_dpa0}_tx 1)" -eq "$(v ${MP_dpb0}_rx 1)" ]
check "nothing bypassed the dataplane" [ "$(v ${MP_dpa0}_tx 4)" -eq 0 ]

echo "== dataplane: 3% loss"
loss $NSA dpa0 300
lost=$(udp $NSA 10.77.0.2 5201 20M 10)
check "FEC turned on (parity ratio $(v ${MP_dpa0}_tx 6))" [ "$(v ${MP_dpa0}_tx 6)" -gt 0 ]
check "peer reports the loss ($(v ${MP_dpa0}_tx 32) bp)" [ "$(v ${MP_dpa0}_tx 32)" -ge 150 ]
check "FEC rebuilt packets ($(v ${MP_dpb0}_rx 6))" [ "$(v ${MP_dpb0}_rx 6)" -gt 0 ]
check "ARQ retransmitted ($(v ${MP_dpa0}_tx 13))" [ "$(v ${MP_dpa0}_tx 13)" -gt 0 ]
check "no bad rebuilds" [ "$(v ${MP_dpb0}_rx 34)" -eq 0 ]
check "UDP loss after repair below 0.3 % (got $lost/100 %)" [ "${lost:-9999}" -lt 30 ]
check "status shows DEGRADED and FEC ON" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dpa0 | grep -q 'DEGRADED' && $STATUS -m $MAPS -c $CONF/$NSA dpa0 detail | grep -q 'FEC         ON'"
check "status one-line output" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -1 dpa0 | grep -q 'fec=on'"
# table (the default): a header, one row per interface, FRR style
$STATUS -m $MAPS -c $CONF/$NSA > $CONF/status-table.txt
check "status table: header and a DEGRADED row with FEC on" sh -c "grep -q '^ *Interface  *Peer  *State  *Health  *Out Loss' $CONF/status-table.txt && grep -Eq '^[*!S]* *dpa0 +[0-9a-f:]{17} +Up +DEGRADED +[0-9]+\.[0-9]{2}% .* 1:[0-9]+\$' $CONF/status-table.txt"
check "status table: a missing interface is NOT RUNNING" sh -c "$STATUS -m $MAPS -c $CONF/$NSA dpa0 nosuch0 | grep -Eq '^ *nosuch0 +- +- +NOT RUNNING'"
# JSON: valid, and the same values as -1
$STATUS -m $MAPS -c $CONF/$NSA dpa0 nosuch0 json > $CONF/status.json
check "status json: valid, health and FEC as in -1" python3 -I -c "
import json, sys
d = json.load(open('$CONF/status.json'))['interfaces']
a = d['dpa0']
assert a['health'] == 'DEGRADED' and a['fec']['state'] == 'on' and a['fec']['ratio'] >= 2, a['health']
assert a['outbound']['lossBp'] > 0 and isinstance(a['outbound']['congested'], bool)
assert d['nosuch0']['health'] == 'NOT RUNNING'
"
check "status -j and --json give the same document" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -j dpa0 | python3 -I -c 'import json,sys; json.load(sys.stdin)' && $STATUS -m $MAPS -c $CONF/$NSA --json dpa0 | python3 -I -c 'import json,sys; json.load(sys.stdin)'"
read del bad < <(verify $NSA 10.77.0.2 6001 6000 2000 1400)
check "every delivered datagram intact ($bad corrupt), ${del}/1000 delivered" [ "$bad" -eq 0 -a "$del" -ge 995 ]
read del bad < <(verify $NSA 10.77.0.2 6002 3000 2000 100)
check "small datagrams intact ($bad corrupt), ${del}/1000 delivered" [ "$bad" -eq 0 -a "$del" -ge 995 ]

echo "== dataplane: cool down"
loss $NSA dpa0 0
ip netns exec $NSB iperf3 -s -p 5202 -1 -D >/dev/null 2>&1; sleep 0.5
A iperf3 -c 10.77.0.2 -p 5202 -u -b 5M -l 1400 -t 16 >/dev/null 2>&1 &
sleep 5; on_at_5=$(v ${MP_dpa0}_tx 6); wait
check "FEC still on 5 s after the loss stopped" [ "$on_at_5" -gt 0 ]
check "FEC off after the 10 s cool down" [ "$(v ${MP_dpa0}_tx 6)" -eq 0 ]

echo "== dataplane: FEC only, TCP under 2% loss both ways"
install $NSA dpa0 --arq-with-fec off --fec-mode on && install $NSB dpb0 --arq-with-fec off --fec-mode on
loss $NSA dpa0 200; loss $NSB dpb0 200
# rate limit with room to queue: a qdisc drop is a local drop, see loss()
A tc qdisc replace dev dpa0 root tbf rate 20mbit burst 20k latency 400ms
head -c 15000000 /dev/urandom > $CONF/tx15.bin
before=$(csum_errors $NSB)
tcp_copy 5003 10.77.0.2 $CONF/tx15.bin $CONF/rx15.bin 90
if cmp -s $CONF/tx15.bin $CONF/rx15.bin; then pass "TCP 15 MB intact"
else
    fail "TCP 15 MB intact: $(stat -c %s $CONF/rx15.bin 2>/dev/null || echo 0) of 15000000 bytes, $(cmp $CONF/tx15.bin $CONF/rx15.bin 2>&1 | head -1), $(cmp -l $CONF/tx15.bin $CONF/rx15.bin 2>/dev/null | wc -l) bytes differ"
    cp $CONF/rx15.bin /tmp/bpfc-dp-rx15.bin 2>/dev/null; cp $CONF/tx15.bin /tmp/bpfc-dp-tx15.bin
    echo "    (kept as /tmp/bpfc-dp-tx15.bin and /tmp/bpfc-dp-rx15.bin; B rx: $(for k in 2 3 4 5 6 8 9 34 37; do printf '%s=%s ' $k $(v ${MP_dpb0}_rx $k); done))"
fi
check "FEC rebuilt packets ($(v ${MP_dpb0}_rx 6)), none bad" [ "$(v ${MP_dpb0}_rx 6)" -gt 0 -a "$(v ${MP_dpb0}_rx 34)" -eq 0 ]
check "no TCP checksum errors" [ "$(csum_errors $NSB)" -eq "$before" ]
check "ARQ held back while FEC is on" [ "$(v ${MP_dpa0}_tx 15)" -gt 0 -a "$(v ${MP_dpa0}_tx 13)" -eq 0 ]
A tc qdisc del dev dpa0 root

echo "== dataplane: two interfaces are independent"
install $NSA dpa0 && install $NSB dpb0 && install $NSA dpa1 && install $NSB dpb1
loss $NSA dpa0 0; loss $NSB dpb0 0; loss $NSA dpa1 400
udp $NSA 10.77.0.2 5204 10M 5 >/dev/null &
udp $NSA 10.77.1.2 5205 10M 5 >/dev/null; wait
check "lossy dpa1 has FEC on" [ "$(v ${MP_dpa1}_tx 6)" -gt 0 ]
check "clean dpa0 has FEC off" [ "$(v ${MP_dpa0}_tx 6)" -eq 0 ]
check "separate maps per interface" [ -e $MAPS/${MP_dpa0}_tx -a -e $MAPS/${MP_dpa1}_tx ]

echo "== dataplane: peer restart"
loss $NSA dpa0 0
A ping -c 300 -i 0.005 -q 10.77.0.2 >/dev/null
gaps=$(v ${MP_dpb0}_rx 5)
install $NSA dpa0
A ping -c 100 -i 0.005 -q 10.77.0.2 >/dev/null
check "receiver resynchronised without counting loss" [ "$(v ${MP_dpb0}_rx 36)" -ge 1 -a "$(v ${MP_dpb0}_rx 5)" -eq "$gaps" ]
# A restart under loss: the window across the restart is empty. It used to
# wrap to an enormous window with no loss, which replaced both averages.
# B averages over 400 packets here, so its estimate is the 3 % before the
# restart (not the clean traffic of the earlier sections).
loss $NSA dpa0 300
$BPFC -m $MAPS -w ${MP_dpb0}_cfg 17 400 >/dev/null
A ping -c 800 -i 0.005 -q 10.77.0.2 >/dev/null
in_before=$(( $(v ${MP_dpb0}_rx 39) / 100 ))
install $NSA dpa0
A ping -c 250 -i 0.005 -q 10.77.0.2 >/dev/null
in_after=$(( $(v ${MP_dpb0}_rx 39) / 100 ))
check "B's inbound loss estimate survives A's restart ($in_before -> $in_after bp)" [ "$in_before" -ge 150 -a "$in_after" -ge 150 -a "$in_after" -le 500 ]
A ping -c 550 -i 0.005 -q 10.77.0.2 >/dev/null
out_after=$(( $(v ${MP_dpa0}_tx 46) / 100 ))
check "A's new estimate starts from B's reports, not the restart ($out_after bp)" [ "$out_after" -ge 150 -a "$out_after" -le 500 ]
$BPFC -m $MAPS -w ${MP_dpb0}_cfg 17 0 >/dev/null
loss $NSA dpa0 0

echo "== dataplane: FEC that cannot keep up counts as congestion"
install $NSA dpa0 && install $NSB dpb0
loss $NSA dpa0 500
A ping -c 1500 -i 0.01 -s 1000 -q 10.77.0.2 >/dev/null
check "5 % loss: repaired, parity scaled to the loss (1:$(v ${MP_dpa0}_tx 6), left $(( $(v ${MP_dpa0}_tx 47) / 100 )) bp)" \
    [ "$(v ${MP_dpa0}_tx 50)" -eq 0 -a "$(v ${MP_dpa0}_tx 16)" -eq 0 -a "$(v ${MP_dpa0}_tx 6)" -ge 3 -a "$(v ${MP_dpa0}_tx 6)" -le 7 ]
install $NSA dpa0 && install $NSB dpb0
loss $NSA dpa0 2500
A ping -c 2000 -i 0.01 -s 1000 -q 10.77.0.2 >/dev/null
check "25 % loss: the most parity still leaves loss, fixed 1:8 instead (1:$(v ${MP_dpa0}_tx 6), left $(( $(v ${MP_dpa0}_tx 47) / 100 )) bp)" \
    [ "$(v ${MP_dpa0}_tx 50)" -eq 1 -a "$(v ${MP_dpa0}_tx 16)" -eq 1 -a "$(v ${MP_dpa0}_tx 6)" -eq 8 ]
check "status explains it" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dpa0 | grep -q 'the most parity still left loss' && $STATUS -m $MAPS -c $CONF/$NSA dpa0 | grep -Eq '^\\*! +dpa0 ' && $STATUS -m $MAPS -c $CONF/$NSA -1 dpa0 | grep -q 'repair_failing=1'"
check "status: POOR" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -1 dpa0 | grep -q 'health=\"POOR\"'"
loss $NSA dpa0 0

echo "== satellite: 800 ms RTT (geo profile)"
# A <-> emulator (400 ms each way) <-> B, on a new pair of interfaces
ip netns add $NSM
ip link add dps0 netns $NSA type veth peer name dpm0 netns $NSM
ip link add dps1 netns $NSB type veth peer name dpm1 netns $NSM
for i in dpm0 dpm1; do ip -n $NSM link set $i up; ip netns exec $NSM ethtool -K $i gro off tso off gso off >/dev/null 2>&1; done
setup $NSA dps0 10.77.2.1; setup $NSB dps1 10.77.2.2
ip netns exec $NSM python3 -I tests/link-emulator.py dpm0 dpm1 400 2> $CONF/emulator.log & EMU_PID=$!
sleep 0.5
install $NSA dps0 --profile geo && install $NSB dps1 --profile geo
A ping -c 2 -W 3 -q 10.77.2.2 >/dev/null
rtt=$(A ping -c 3 -W 3 -q 10.77.2.2 | awk -F/ '/^rtt/{printf "%d", $5}')
check "RTT through the emulator about 800 ms (${rtt} ms)" [ "${rtt:-0}" -ge 790 -a "${rtt:-0}" -le 900 ]
# light traffic, no loss: reports arrive and the floor applies
A ping -c 30 -i 0.1 -W 3 -q 10.77.2.2 >/dev/null
check "FEC floor on without loss (1:$(v ${MP_dps0}_tx 6), peer measured $(v ${MP_dps0}_tx 32) bp loss)" [ "$(v ${MP_dps0}_tx 6)" -eq 15 ]
head -c 2000000 /dev/urandom > $CONF/tx2.bin
tcp_copy 5004 10.77.2.2 $CONF/tx2.bin $CONF/rx2.bin 90
check "TCP 2 MB intact over 800 ms ($(stat -c %s $CONF/rx2.bin 2>/dev/null || echo 0) of 2000000 bytes)" cmp -s $CONF/tx2.bin $CONF/rx2.bin
sleep 2.5   # let the emulator write its drop totals
drops=$(awk '/emulator drops/ {n = $5 + $8 + $11 + $14} END {print n + 0}' $CONF/emulator.log)
check "link emulator kept up during TCP bursts ($drops frames lost in the emulator)" [ "$drops" -eq 0 ]
loss $NSA dps0 200
read del bad < <(verify $NSA 10.77.2.2 6003 6000 700 1400)
check "2 % loss: datagrams intact ($bad corrupt), ${del}/1000 delivered" [ "$bad" -eq 0 -a "$del" -ge 996 ]
check "FEC rebuilt ($(v ${MP_dps1}_rx 6)) and ARQ recovered ($(v ${MP_dps1}_rx 7))" [ "$(v ${MP_dps1}_rx 6)" -gt 0 -a "$(v ${MP_dps1}_rx 7)" -gt 0 ]
check "ARQ ring held every NAKed packet ($(v ${MP_dps0}_tx 14) missing)" [ "$(v ${MP_dps0}_tx 14)" -eq 0 ]
check "gaps match the loss ($(v ${MP_dps1}_rx 5) gaps, $(v ${MP_dps1}_rx 36) resyncs)" [ "$(v ${MP_dps1}_rx 5)" -lt 300 -a "$(v ${MP_dps1}_rx 36)" -eq 0 ]
# few probe samples at the geo profile's 10 s interval: the largest counts
# (B measures A -> B; only A sends packets big enough to probe with)
A ping -c 15 -i 0.1 -s 56 -q 10.77.2.2 >/dev/null     # small: a report, no new sample
n=$(v ${MP_dps1}_rx 43); want=$(cap_expected ${MP_dps1}_rx)
check "capacity estimate with $n samples is the sample the count calls for ($(v ${MP_dps1}_rx 19) kbit/s, want $want)" [ "$n" -ge 1 -a "$(v ${MP_dps1}_rx 19)" -eq "${want:-0}" ]
check "status shows the profile and no sizing warning" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'Profile     geo, sized for 20.0 Mbit/s and 800 ms' && ! $STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q Sizing"
install $NSA dps0 && install $NSB dps1
loss $NSA dps0 200
ip netns exec $NSB iperf3 -s -p 5206 -1 -D >/dev/null 2>&1; sleep 0.5
A iperf3 -c 10.77.2.2 -p 5206 -u -b 8M -l 1400 -t 12 >/dev/null 2>&1 & IPERF_PID=$!
sleep 9
check "default sizing: status warns that the ARQ ring is too small" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'Sizing      WARNING: .*needs an ARQ ring' && $STATUS -m $MAPS -c $CONF/$NSA dps0 | grep -Eq '^[*!]*S +dps0 '"
wait $IPERF_PID
check "default sizing: most NAKed packets already gone ($(v ${MP_dps0}_tx 14) gone, $(v ${MP_dps0}_tx 13) retransmitted)" [ "$(v ${MP_dps0}_tx 14)" -gt "$(v ${MP_dps0}_tx 13)" ]

echo "== asymmetric link: loss estimate and packet pairs"
# A -> B 20 Mbit/s, B -> A 10 Mbit/s, 50 ms +- 5 ms each way, 3 % loss, the
# way netem shapes (a packet never leaves before the one ahead of it)
kill $EMU_PID 2>/dev/null; wait $EMU_PID 2>/dev/null
pkill -f "^python3 -I tests/link-emulator.py dpm0 dpm1" 2>/dev/null
for i in $(seq 25); do pgrep -f "^python3 -I tests/link-emulator.py dpm0 dpm1" >/dev/null || break; sleep 0.2; done
ip netns exec $NSM python3 -I tests/link-emulator.py dpm0 dpm1 50 --a2b rate=20m,jitter=5,loss=3 --b2a rate=10m,jitter=5,loss=3 2> $CONF/emulator.log & EMU_PID=$!
sleep 0.5
install $NSA dps0 --probe-rate 10 && install $NSB dps1 --probe-rate 10
check "probe-rate 10 means a probe every 100 ms" grep -q "probe_ms=100 " $CONF/$NSA/dps0/egress/100.bpfc
A ping -c 600 -i 0.025 -s 1200 -q 10.77.2.2 >/dev/null & PA=$!
B ping -c 600 -i 0.025 -s 1200 -q 10.77.2.1 >/dev/null
wait $PA
lo=$(( $(v ${MP_dps0}_tx 46) / 100 )); li=$(( $(v ${MP_dps0}_rx 39) / 100 ))
check "averaged loss near the 3 % on the link (out $lo bp, in $li bp)" [ "$lo" -ge 150 -a "$lo" -le 500 -a "$li" -ge 150 -a "$li" -le 500 ]
check "status reports the average" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'Loss  .*(average of'"
ca=$(v ${MP_dps0}_rx 19); cb=$(v ${MP_dps1}_rx 19)
check "packet pairs measure each direction: B -> A ~10 Mbit/s ($ca kbit/s), A -> B ~20 Mbit/s ($cb kbit/s)" [ "$ca" -ge 8000 -a "$ca" -le 13500 -a "$cb" -ge 16000 -a "$cb" -le 28000 ]
B ping -c 15 -i 0.1 -s 56 -q 10.77.2.1 >/dev/null
n=$(v ${MP_dps0}_rx 43); want=$(cap_expected ${MP_dps0}_rx)
check "capacity estimate with $n samples is the sample the count calls for ($(v ${MP_dps0}_rx 19) kbit/s, want $want)" [ "$(v ${MP_dps0}_rx 19)" -eq "${want:-0}" ]
# capacity-window: after B -> A drops from 10 to 5 Mbit/s, A's estimate
# follows within the window; the 16-sample ring alone would keep 10 Mbit/s
# until 13 new samples are in
$STATUS -m $MAPS -c $CONF/$NSA set dps0 capacity-window 2s >/dev/null
kill $EMU_PID 2>/dev/null; wait $EMU_PID 2>/dev/null
for i in $(seq 25); do pgrep -f "^python3 -I tests/link-emulator.py dpm0 dpm1" >/dev/null || break; sleep 0.2; done
ip netns exec $NSM python3 -I tests/link-emulator.py dpm0 dpm1 50 --a2b rate=20m,jitter=5 --b2a rate=5m,jitter=5 2> $CONF/emulator.log & EMU_PID=$!
sleep 0.5
A ping -c 160 -i 0.025 -s 1200 -q 10.77.2.2 >/dev/null & PA=$!
B ping -c 160 -i 0.025 -s 1200 -q 10.77.2.1 >/dev/null
wait $PA
B ping -c 15 -i 0.1 -s 56 -q 10.77.2.1 >/dev/null      # a report, no new sample
ca5=$(v ${MP_dps0}_rx 19); used=$(v ${MP_dps0}_rx 57)
check "capacity-window 2s: B -> A estimate follows 10 -> 5 Mbit/s ($ca5 kbit/s from $used samples)" [ "$ca5" -ge 3500 -a "$ca5" -le 7000 ]
check "status shows the window" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'in the last 2.0 s)' && $STATUS -m $MAPS -c $CONF/$NSA -j dps0 | grep -q '\"capacityWindowMsec\": 2000'"
$STATUS -m $MAPS -c $CONF/$NSA unset dps0 capacity-window >/dev/null
check "the sender sees the peer's measurement of its direction" [ "$(v ${MP_dps0}_tx 36)" -ge 16000 -a "$(v ${MP_dps1}_tx 36)" -le 13500 ]

echo "== framed link (Starlink-like): trains vs pairs"
# As FRR's satrelay test bed: traffic leaves in 1.33 ms frames; every 15 s
# (at :12, :27, :42, :57) the rate is drawn again, +/- 40 %, and 30 % of the
# packets are lost for 200 ms. A -> B 40 Mbit/s ("down"), B -> A 15 Mbit/s
# ("up"), 20 ms each way. The estimate's median over the run is compared
# with the median of the true rates at the same moments.
FRAMED="frame=1.33,redraw=15,vary=40,burst=30:200"
# framed_run <seconds> [generator options]: traffic both ways, A's and B's
# estimate (of the direction they receive) sampled every 0.5 s after 9 s
framed_run() {
    local secs=$1; shift
    kill $EMU_PID 2>/dev/null
    pkill -f "^python3 -I tests/link-emulator.py dpm0 dpm1" 2>/dev/null
    for i in $(seq 25); do pgrep -f "^python3 -I tests/link-emulator.py dpm0 dpm1" >/dev/null || break; sleep 0.2; done
    pkill -9 -f "^python3 -I tests/link-emulator.py dpm0 dpm1" 2>/dev/null
    wait $EMU_PID 2>/dev/null
    rm -f $CONF/rate-ab $CONF/rate-ba $CONF/est-a $CONF/est-b
    ip netns exec $NSM python3 -I tests/link-emulator.py dpm0 dpm1 20 \
        --a2b rate=40m,$FRAMED,ratelog=$CONF/rate-ab --b2a rate=15m,$FRAMED,ratelog=$CONF/rate-ba 2> $CONF/emulator.log & EMU_PID=$!
    sleep 0.5
    install $NSA dps0 --profile leo "$@" && install $NSB dps1 --profile leo "$@" || { check "framed: install" false; return 1; }
    A ping -c $((secs * 50)) -i 0.02 -s 1200 -q 10.77.2.2 >/dev/null & local PA=$!
    B ping -c $((secs * 50)) -i 0.02 -s 1200 -q 10.77.2.1 >/dev/null & local PB=$!
    sleep 9
    local end=$(( $(date +%s) + secs - 10 ))
    while [ "$(date +%s)" -lt $end ]; do
        echo "$(date +%s.%N) $(v ${MP_dps1}_rx 19)" >> $CONF/est-b     # A -> B, measured by B
        echo "$(date +%s.%N) $(v ${MP_dps0}_rx 19)" >> $CONF/est-a     # B -> A, measured by A
        sleep 0.5
    done
    wait $PA $PB
}
# framed_ratio <estimates> <rate log>: median estimate * 100 / median true rate
framed_ratio() {
    awk 'NR == FNR { t[NR] = $1; r[NR] = $2 / 1000; n = NR; next }
         $2 > 0 { rate = 0; for (i = 1; i <= n; i++) if (t[i] <= $1) rate = r[i]
                  if (rate > 0) { e[++m] = $2; q[m] = rate } }
         function med(a, k,   i, j, x) { for (i = 2; i <= k; i++) { x = a[i]; for (j = i - 1; j > 0 && a[j] > x; j--) a[j + 1] = a[j]; a[j + 1] = x } return a[int((k + 1) / 2)] }
         END { if (m < 5) { print 0; exit } me = med(e, m); mq = med(q, m); printf "%d %d %d\n", me * 100 / mq, me, mq }' "$2" "$1"
}
framed_run 50 --probe-train 0 --capacity-percentile 0
read pr_b pe_b pq_b < <(framed_ratio $CONF/est-b $CONF/rate-ab)
read pr_a pe_a pq_a < <(framed_ratio $CONF/est-a $CONF/rate-ba)
check "pairs on a framed link read too fast: down ${pe_b:-0} for ${pq_b:-0} kbit/s ($pr_b %), up ${pe_a:-0} for ${pq_a:-0} ($pr_a %)" [ "${pr_a:-0}" -ge 140 ]
framed_run 50
read tr_b te_b tq_b < <(framed_ratio $CONF/est-b $CONF/rate-ab)
read tr_a te_a tq_a < <(framed_ratio $CONF/est-a $CONF/rate-ba)
check "leo profile (20 ms trains, median): down ${te_b:-0} for ${tq_b:-0} kbit/s ($tr_b %)" [ "${tr_b:-0}" -ge 80 -a "${tr_b:-0}" -le 125 ]
check "leo profile (20 ms trains, median): up ${te_a:-0} for ${tq_a:-0} kbit/s ($tr_a %)" [ "${tr_a:-0}" -ge 80 -a "${tr_a:-0}" -le 125 ]
check "train length follows the rate (A sent $(v ${MP_dps0}_tx 69) train packets in $(v ${MP_dps0}_tx 11) trains)" \
    [ "$(v ${MP_dps0}_tx 11)" -gt 0 -a $(( $(v ${MP_dps0}_tx 69) / ($(v ${MP_dps0}_tx 11) + 1) )) -ge 30 ]
check "fillers are not duplicates (B: $(v ${MP_dps1}_rx 96) fillers, $(v ${MP_dps1}_rx 3) duplicates)" \
    [ "$(v ${MP_dps1}_rx 96)" -gt 100 -a "$(v ${MP_dps1}_rx 3)" -lt 10 ]
check "status shows trains and the percentile" sh -c "$STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'trains of 20 ms' && $STATUS -m $MAPS -c $CONF/$NSA -d dps0 | grep -q 'percentile 50'"

echo
echo "$PASSES passed, $FAILS failed"
[ $FAILS -eq 0 ]
