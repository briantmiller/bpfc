#!/bin/bash
#
# Flow keys and the commands built on them: hash, pack, unpack, flow-key,
# seen, over-rate, count, prefix-map / in, host/net/port, dscp/ecn, set
# src-port/dst-port, and bpfc -H / -K / -V / -w / -x. Every key a program
# computes from a packet is compared with the one bpfc -H computes from the
# same values, so the two implementations cannot drift apart.
#
#   tests/test-keys.sh          (root; needs python3 for the packet sender)

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root keys
require_cmds keys python3 ip tc

BPFC=$PWD/bpfc
SEND=$PWD/tests/keys-send.py
MAPS=/run/bpfc-keys-$$

cleanup() {
	ip netns del KA 2>/dev/null
	ip netns del KB 2>/dev/null
	umount $MAPS 2>/dev/null
	rmdir $MAPS 2>/dev/null
}
trap 'cleanup; rm -f "$TESTS_FAILED_FILE"' EXIT
cleanup
mkdir -p $MAPS && mount -t bpf bpffs $MAPS || { test_fail "mount bpffs on $MAPS"; exit 1; }

ip netns add KA
ip netns add KB
ip link add ka0 netns KA type veth peer name kb0 netns KB
for n in KA KB; do ip -n $n link set lo up; done
ip -n KA link set ka0 up
ip -n KB link set kb0 up
ip -n KA addr add 10.88.0.1/24 dev ka0
ip -n KB addr add 10.88.0.2/24 dev kb0
ip -n KA -6 addr add fd88::1/64 dev ka0 nodad 2>/dev/null
ip -n KB -6 addr add fd88::2/64 dev kb0 nodad 2>/dev/null
AMAC=$(ip -n KA -o link show ka0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')
BMAC=$(ip -n KB -o link show kb0 | sed 's/.*link\/ether \([0-9a-f:]*\).*/\1/')

A() { ip netns exec KA "$@"; }
B() { ip netns exec KB "$@"; }
send() { A python3 -I $SEND ka0 $BMAC "$@"; sleep 0.2; }
H() { $BPFC -H "$*"; }
# v MAP KEY: the value at KEY as 0x + 16 hex digits ("" when there is none)
v() { $BPFC -m $MAPS -r $1 | awk -v k=$(printf '0x%016x' $2) '$3 == k { print $6 }'; }
eqk() { local name=$1 got=$2 want=$3; check "$name ($got)" [ -n "$got" -a "$got" = "$want" ]; }

echo "== compile: every key form loads (verifier)"
ok() { local name=$1; shift; if $BPFC -m $MAPS -T "$@" >/dev/null 2>&1; then test_pass "$name"; else test_fail "$name"; $BPFC -m $MAPS -T "$@" 2>&1 | tail -3; fi; }
bad() { local name=$1; shift; if $BPFC -m $MAPS -T "$@" >/dev/null 2>&1; then test_fail "$name (accepted)"; else test_pass "$name"; fi; }
ok  KC-hash-5tuple   "hash K 64 ip-src ip-dst ip-proto src-port dst-port"
ok  KC-hash-sym      "hash K 64 symmetric ip-src ip-dst ip-proto src-port dst-port"
ok  KC-hash-buckets  "hash B buckets 3 symmetric ip-src ip-dst ip-proto src-port dst-port"
ok  KC-hash-ip6      "hash K 64 symmetric ip6-src ip6-dst ip6-proto src-port dst-port"
ok  KC-hash-ip6-pfx  "hash K 32 ip6-src/64 ip6-dst/48 ip6-src/96"
ok  KC-pack-ip6-pfx  "pack K ip6-src/48 ip6-dst/16"
ok  KC-v6-matches    "match host fd00::1; drop; end-match; match net fd00::/8; drop; end-match; match port 53; drop; end-match; match icmp6; drop; end-match"
ok  KC-v6-prefix-map "prefix-map P6 ipv6; match ip6-src in P6 V; drop; end-match"
ok  KC-hash-seed     "decl S 8; set val S 5; hash K 20 seed %S ip-src icmp-id"
ok  KC-hash-get      "hash K 64 gre-key skb-mark bytes 14 4"
ok  KC-pack          "pack K vlan-id dscp ecn ip-ttl ip-proto icmp-id"
ok  KC-pack-rev      "pack K reverse ip-src src-port dst-port"
ok  KC-pack-pfx      "pack K ip-src/24 ip-dst/24 dst-port"
ok  KC-pack-mac      "pack K src-mac eth-proto"
ok  KC-unpack        "pack K ip-src src-port; unpack %K A:32 P:16"
ok  KC-flow-key      "get flow-key K; get flow-key R reverse; get flow-key S symmetric"
ok  KC-getfields     "get src-port P; get dst-port Q; get dscp D; get ecn E; get ip-ttl T; get icmp-id I; get icmp-type Y"
ok  KC-seen          "match seen DUP ip-src ip-dst ip-proto ip-ident within 50ms; drop; end-match"
ok  KC-seen-refresh  "match seen IDLE symmetric ip-src ip-dst within 2s refresh; drop; end-match"
ok  KC-over-pps      "match over-rate RL1 ip-src 10/s burst 20; drop; end-match"
ok  KC-over-bit      "match over-rate RL2 ip-src/16 50mbit burst 256k; set dscp af13; else; set dscp af11; end-match"
ok  KC-count         "count CP CB vlan-id ip-src"
ok  KC-count-var     "hash K 64 ip-src; count CV %K"
ok  KC-prefix        "prefix-map PFX; match ip-src in PFX; drop; end-match; get ip-dst D; if %D in PFX V; drop; end-if"
ok  KC-host-net      "match host 10.0.0.1; drop; end-match; match net 10.0.0.0/8; drop; end-match"
ok  KC-port          "match port 53; drop; end-match; match src-port 1000-2000; drop; end-match; match dst-port 443; drop; end-match"
ok  KC-dscp          "match dscp ef; set dscp cs1; end-match; match ecn ce; set ecn ect0; end-match"
ok  KC-set-port      "decl P 2; set val P 80; set src-port 1234; set dst-port %P"
ok  KC-xdp           -d xdp "hash K 64 symmetric ip-src ip-dst ip-proto src-port dst-port; match seen XD %K within 50ms; drop; end-match; count XC vlan-id; match over-rate XR ip-src 1mbit; drop; end-match"
ok  KC-raw-ip        -s L3OFF=0 "match ip; hash K 64 ip-src ip-dst src-port dst-port; count RC ip-src; end-match"
bad KC-pack-too-wide "pack K ip-src ip-dst ip-proto"
bad KC-pack-ip6      "pack K ip6-src"
bad KC-mixed-family  "hash K 64 ip-src ip6-dst"
bad KC-sym-partner   "hash K 64 symmetric ip-src ip-proto"
bad KC-sym-prefix    "hash K 64 symmetric ip-src/24 ip-dst"
bad KC-raw-mac       -s L3OFF=0 "pack K src-mac"
bad KC-pack-const    "pack K 6 ip-src"
bad KC-seen-unit     "match seen D ip-src within 50; drop; end-match"
bad KC-in-not-prefix "match ip-src in NOTPFX; drop; end-match"
bad KC-in-family     "prefix-map P4X; match ip6-src in P4X; drop; end-match"
bad KC-pack-ip6-wide "pack K ip6-src/64 dst-port"

echo "== bpfc -H"
eqk "-H pack: src << 32 | dst" "$(H pack ip-src=10.88.0.1 ip-dst=10.88.0.2)" 0x0a5800010a580002
eqk "-H pack: prefixes keep the network bits" "$(H pack ip-src/24=10.88.0.77 dst-port=443)" 0x0000000a580001bb
eqk "-H pack: names (dscp ef, ecn ce)" "$(H pack dscp=ef ecn=ce)" 0x00000000000000bb
FWD="ip-src=10.0.0.1 ip-dst=192.0.2.10 ip-proto=6 src-port=51515 dst-port=443"
REV="ip-src=192.0.2.10 ip-dst=10.0.0.1 ip-proto=6 src-port=443 dst-port=51515"
eqk "-H symmetric: both directions one key" "$(H hash 64 symmetric $FWD)" "$(H hash 64 symmetric $REV)"
eqk "-H reverse: the reply's key" "$(H hash 64 reverse $FWD)" "$(H hash 64 $REV)"
check "-H plain: directions differ" [ "$(H hash 64 $FWD)" != "$(H hash 64 $REV)" ]
B3=$(H hash buckets 3 $FWD)
check "-H buckets 3 is 0-2 ($B3)" [ $((B3)) -le 2 ]
check "-H 16 bits fit 16 bits" [ $(( $(H hash 16 $FWD) >> 16 )) -eq 0 ]
check "-H seed changes the key" [ "$(H hash 64 seed 1 $FWD)" != "$(H hash 64 $FWD)" ]
check "-H rejects a missing value" sh -c "! $BPFC -H 'hash 64 ip-src' 2>/dev/null"

echo "== keys from packets equal bpfc -H"
PROG='array-map KH 32; array-map KF 32; array-map KS 32; array-map KR 32; array-map KP 32; array-map KQ 32;
array-map KB 32; array-map KN 32; array-map KX 32; array-map KM 32; array-map KA 32;
array-map KH6 32; array-map KS6 32; array-map KP6 32;
match ip;
  get ip-ident I;
  hash K 64 ip-src ip-dst ip-proto src-port dst-port; set map KH %I %K;
  get flow-key K; set map KF %I %K;
  hash K 64 symmetric ip-src ip-dst ip-proto src-port dst-port; set map KS %I %K;
  hash K 64 reverse ip-src ip-dst ip-proto src-port dst-port; set map KR %I %K;
  pack K ip-src ip-dst; set map KP %I %K;
  pack K vlan-id dscp ecn ip-ttl ip-proto icmp-id; set map KQ %I %K;
  hash K buckets 7 symmetric ip-src ip-dst; set map KB %I %K;
  hash K 13 seed 99 ip-src/24 ip-tos %I:16; set map KN %I %K;
  pack K ip-src/20 dst-port; set map KX %I %K;
  hash K 40 src-mac dst-mac eth-proto; set map KM %I %K;
end-match;
match ip6;
  get ip6-flow I;
  hash K 64 ip6-src ip6-dst ip6-proto src-port dst-port; set map KH6 %I %K;
  hash K 64 symmetric ip6-src ip6-dst ip6-proto src-port dst-port; set map KS6 %I %K;
  pack K ip6-proto ip6-flow src-port; set map KP6 %I %K;
end-match;
match arp;
  hash K 64 ip-src ip-dst; set map KA 1 %K;
  pack K vlan-id src-mac:8; set map KA 2 %K;
end-match'
if B $BPFC -m $MAPS -i kb0 -d ingress -p 10 "$PROG" >/dev/null; then test_pass "key program attaches"; else test_fail "key program attaches"; fi
$BPFC -m $MAPS -w KA 1 5 >/dev/null; $BPFC -m $MAPS -w KA 2 5 >/dev/null
send proto=udp,src=10.88.0.1,dst=10.88.0.2,sport=1111,dport=2222,ident=1 \
     proto=udp,src=10.88.0.2,dst=10.88.0.1,sport=2222,dport=1111,ident=2 \
     proto=tcp,src=10.88.0.5,dst=10.88.0.9,sport=40000,dport=443,ihl=6,ident=3 \
     proto=udp,sport=5,dport=6,frag=mf,ident=4 \
     proto=udp,sport=5,dport=6,frag=off,ident=5 \
     proto=icmp,icmpid=77,ident=6 \
     proto=udp,vlan=101,tos=184,ttl=33,sport=7,dport=8,ident=7 \
     proto=47,ident=8 \
     proto=132,tos=3,ident=9 \
     l3=6,proto=udp,src=fd88::1,dst=fd88::2,sport=3333,dport=4444,ident=21 \
     l3=6,proto=udp,src=fd88::2,dst=fd88::1,sport=4444,dport=3333,ident=22 \
     l3=6,proto=udp,src=fd88::1,dst=fd88::2,sport=3333,dport=4444,hbh=1,ident=23 \
     l3=arp
T1="ip-src=10.88.0.1 ip-dst=10.88.0.2 ip-proto=17 src-port=1111 dst-port=2222"
T2="ip-src=10.88.0.2 ip-dst=10.88.0.1 ip-proto=17 src-port=2222 dst-port=1111"
eqk "hash 5-tuple, UDP" "$(v KH 1)" "$(H hash 64 $T1)"
eqk "flow-key = hash 64 ip-src ip-dst ip-proto src-port dst-port" "$(v KF 1)" "$(v KH 1)"
eqk "flow-key reverse direction" "$(v KF 2)" "$(H hash 64 $T2)"
eqk "symmetric, forward" "$(v KS 1)" "$(H hash 64 symmetric $T1)"
eqk "symmetric, the reply has the same key" "$(v KS 2)" "$(v KS 1)"
eqk "reverse of the reply = the forward key" "$(v KR 2)" "$(v KH 1)"
eqk "hash TCP behind IP options (IHL 6)" "$(v KH 3)" "$(H hash 64 ip-src=10.88.0.5 ip-dst=10.88.0.9 ip-proto=6 src-port=40000 dst-port=443)"
eqk "first fragment: ports count as 0" "$(v KH 4)" "$(H hash 64 ip-src=10.88.0.1 ip-dst=10.88.0.2 ip-proto=17 src-port=0 dst-port=0)"
eqk "later fragment: the same key" "$(v KH 5)" "$(v KH 4)"
eqk "ICMP: no ports" "$(v KH 6)" "$(H hash 64 ip-src=10.88.0.1 ip-dst=10.88.0.2 ip-proto=1 src-port=0 dst-port=0)"
eqk "GRE: no ports" "$(v KH 8)" "$(H hash 64 ip-src=10.88.0.1 ip-dst=10.88.0.2 ip-proto=47 src-port=0 dst-port=0)"
eqk "SCTP: ports" "$(v KH 9)" "$(H hash 64 ip-src=10.88.0.1 ip-dst=10.88.0.2 ip-proto=132 src-port=27499 dst-port=27499)"
eqk "pack ip-src ip-dst" "$(v KP 1)" 0x0a5800010a580002
eqk "pack vlan-id dscp ecn ip-ttl ip-proto icmp-id (VLAN 101, EF)" "$(v KQ 7)" "$(H pack vlan-id=101 dscp=ef ecn=0 ip-ttl=33 ip-proto=17 icmp-id=0)"
eqk "pack ... icmp-id (echo id 77)" "$(v KQ 6)" "$(H pack vlan-id=0 dscp=0 ecn=0 ip-ttl=64 ip-proto=1 icmp-id=77)"
eqk "pack ecn ce" "$(v KQ 9)" "$(H pack vlan-id=0 dscp=0 ecn=ce ip-ttl=64 ip-proto=132 icmp-id=0)"
eqk "buckets 7 symmetric, both directions" "$(v KB 2)" "$(v KB 1)"
eqk "buckets 7 = bpfc -H" "$(v KB 1)" "$(H hash buckets 7 symmetric ip-src=10.88.0.1 ip-dst=10.88.0.2)"
eqk "seed, prefix, variable" "$(v KN 7)" "$(H hash 13 seed 99 ip-src/24=10.88.0.1 ip-tos=184 %I:16=7)"
eqk "pack ip-src/20 dst-port" "$(v KX 3)" "$(H pack ip-src/20=10.88.0.5 dst-port=443)"
eqk "MACs and EtherType" "$(v KM 1)" "$(H hash 40 src-mac=$AMAC dst-mac=$BMAC eth-proto=0x0800)"
T6="ip6-src=fd88::1 ip6-dst=fd88::2 ip6-proto=17 src-port=3333 dst-port=4444"
eqk "IPv6 hash" "$(v KH6 21)" "$(H hash 64 $T6)"
eqk "IPv6 symmetric, both directions" "$(v KS6 22)" "$(v KS6 21)"
eqk "IPv6 behind a hop-by-hop header: the ports are found" "$(v KH6 23)" "$(H hash 64 ip6-src=fd88::1 ip6-dst=fd88::2 ip6-proto=0 src-port=3333 dst-port=4444)"
eqk "IPv6 pack" "$(v KP6 21)" "$(H pack ip6-proto=17 ip6-flow=21 src-port=3333)"
eqk "ARP: an IPv4 key is absent (0)" "$(v KA 1)" 0x0000000000000000
eqk "ARP: a key of any-packet fields is not" "$(v KA 2)" "$(H pack vlan-id=0 src-mac:8=$AMAC)"
B $BPFC -i kb0 -c

echo "== IPv6: prefixes, fragments, host/net/port, dscp, prefix maps"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'array-map V6K 64; prefix-map P6 64 ipv6;
match ip6;
  get ip6-flow I;
  hash K 64 ip6-src ip6-dst src-port dst-port; set map V6K %I %K;
  pack K ip6-src/48 ip6-dst/16; calc add I 32; set map V6K %I %K;
end-match;
match udp; match dst-port 9200; calc-map add V6C 0 1; end-match; end-match;
match port 9201; calc-map add V6C 1 1; end-match;
match host fd88::7; calc-map add V6C 2 1; end-match;
match net fd99::/16; calc-map add V6C 3 1; end-match;
match dscp ef; calc-map add V6C 4 1; end-match;
match icmp6; calc-map add V6C 5 1; end-match;
if ip6-src in P6 V; calc-map add V6C %V 1; end-if;
match ip6; match dst-port 9202; get src-port SP; set map V6C 6 %SP; get dscp D; set map V6C 7 %D; set dscp af41; end-match; end-match;
continue' >/dev/null || test_fail "IPv6 program attaches"
B $BPFC -m $MAPS -i kb0 -d ingress -p 20 'match ip6; match dst-port 9202; get dscp D; set map V6C 8 %D; end-match; end-match' >/dev/null
$BPFC -m $MAPS -w P6 fd88::/64 10 >/dev/null; $BPFC -m $MAPS -w P6 fd88::8:0/112 11 >/dev/null
send l3=6,proto=udp,src=fd88::1,dst=fd88::2,sport=5,dport=6,frag6=first,ident=1 \
     l3=6,proto=udp,src=fd88::1,dst=fd88::2,sport=5,dport=6,frag6=later,ident=2 \
     l3=6,proto=udp,src=fd88:0:0:0:abcd::1,dst=fd88::2,sport=5,dport=6,ident=3 \
     l3=6,proto=udp,src=fd99::1,dst=fd88::2,dport=9201,hbh=1,ident=4 \
     l3=6,proto=tcp,src=fd88::1,dst=fd88::7,dport=80,ident=5 \
     l3=6,proto=udp,src=fd88::8:5,dst=fd88::2,sport=4321,dport=9202,tos=184,ident=6 \
     l3=6,proto=icmp,src=fd88::1,dst=fd88::2,ident=7
eqk "IPv6 first fragment: ports 0" "$(v V6K 1)" "$(H hash 64 ip6-src=fd88::1 ip6-dst=fd88::2 src-port=0 dst-port=0)"
eqk "IPv6 later fragment: the same key" "$(v V6K 2)" "$(v V6K 1)"
eqk "pack ip6-src/48 ip6-dst/16" "$(v V6K 35)" "$(H pack ip6-src/48=fd88:0:0:0:abcd::1 ip6-dst/16=fd88::2)"
check "match port: IPv6 behind a hop-by-hop header ($(( $(v V6C 1) )))" [ $(( $(v V6C 1) )) -eq 1 ]
check "match host: an IPv6 destination ($(( $(v V6C 2) )))" [ $(( $(v V6C 2) )) -eq 1 ]
check "match net: an IPv6 source prefix ($(( $(v V6C 3) )))" [ $(( $(v V6C 3) )) -eq 1 ]
check "match dscp ef: the traffic class ($(( $(v V6C 4) )))" [ $(( $(v V6C 4) )) -eq 1 ]
check "match icmp6 ($(( $(v V6C 5) )))" [ $(( $(v V6C 5) )) -eq 1 ]
check "IPv6 prefix map: longest match (/64: $(( $(v V6C 10) )), /112: $(( $(v V6C 11) )))" [ $(( $(v V6C 10) )) -eq 5 -a $(( $(v V6C 11) )) -eq 1 ]
check "-r lists IPv6 prefixes" sh -c "$BPFC -m $MAPS -r P6 | grep -qx 'fd88::8:0/112 11'"
eqk "get src-port, IPv6" "$(v V6C 6)" "$(printf 0x%016x 4321)"
eqk "get dscp, IPv6 (ef)" "$(v V6C 7)" "$(printf 0x%016x 46)"
eqk "set dscp af41 on IPv6, seen by the next program" "$(v V6C 8)" "$(printf 0x%016x 34)"
check "-K decodes an IPv6 prefix" sh -c "$BPFC -m $MAPS -w V6C 'pack ip6-src/48=fd88:1:2::9' 7 >/dev/null && $BPFC -m $MAPS -r V6C -K 'ip6-src/48' | grep -qx 'fd88:1:2::/48 7'"
B $BPFC -i kb0 -c

echo "== unpack, get, set"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'match udp; match dst-port 6000;
  pack K ip-src src-port; unpack %K A:32 P:16; set map KU 1 %A; set map KU 2 %P;
  get src-port S; set map KU 3 %S; get dscp D; set map KU 4 %D; get ip-ttl T; set map KU 5 %T;
  set dst-port 5555; set dscp af41; set ecn ect0;
end-match; end-match; continue' >/dev/null
B $BPFC -m $MAPS -i kb0 -d ingress -p 20 'match udp; match dst-port 5555; get dscp D; set map KU 6 %D; get ecn E; set map KU 7 %E; end-match; end-match' >/dev/null
B timeout 3 python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.88.0.2", 5555)); s.settimeout(2.5); print(s.recv(100).decode())' > /tmp/keys-rx.$$ 2>/dev/null &
RX=$!
sleep 0.3
send proto=udp,src=10.88.0.1,dst=10.88.0.2,sport=1234,dport=6000,tos=0,ttl=9,ident=1,len=5
wait $RX
eqk "unpack: the address" "$(v KU 1)" "$(printf 0x%016x $(( 0x0a580001 )))"
eqk "unpack: the port" "$(v KU 2)" "$(printf 0x%016x 1234)"
eqk "get src-port" "$(v KU 3)" "$(printf 0x%016x 1234)"
eqk "get ip-ttl" "$(v KU 5)" "$(printf 0x%016x 9)"
eqk "set dscp af41 (34)" "$(v KU 6)" "$(printf 0x%016x 34)"
eqk "set ecn ect0 (2), dscp kept" "$(v KU 7)" "$(printf 0x%016x 2)"
check "set dst-port rewrote the port and the UDP checksum: delivered to 5555" grep -q kkkkk /tmp/keys-rx.$$
rm -f /tmp/keys-rx.$$
B $BPFC -i kb0 -c

echo "== seen"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'match udp; match dst-port 9001;
  match seen SEEN ip-src ip-dst ip-ident within 300ms; calc-map add SC 1 1; drop; end-match;
  calc-map add SC 0 1; drop;
end-match; end-match;
match udp; match dst-port 9002;
  match seen SEENR ip-src ip-dst within 300ms refresh; calc-map add SC 3 1; drop; end-match;
  calc-map add SC 2 1; drop;
end-match; end-match' >/dev/null
send proto=udp,dport=9001,ident=500,count=3 proto=udp,dport=9001,ident=501
check "seen: first copies pass, duplicates are seen ($(( $(v SC 0) )) new, $(( $(v SC 1) )) seen)" [ $(( $(v SC 0) )) -eq 2 -a $(( $(v SC 1) )) -eq 2 ]
sleep 0.4
send proto=udp,dport=9001,ident=500
check "seen: after the window, the key is new again" [ $(( $(v SC 0) )) -eq 3 ]
send proto=udp,dport=9002,count=6,gap=0.1
check "seen refresh: 6 packets 100 ms apart, all but the first seen ($(( $(v SC 3) )))" [ $(( $(v SC 2) )) -eq 1 -a $(( $(v SC 3) )) -eq 5 ]
B $BPFC -i kb0 -c

echo "== over-rate"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'match udp; match dst-port 9010;
  match over-rate RLP ip-src 10/s burst 5; calc-map add RC 1 1; drop; end-match; calc-map add RC 0 1; drop;
end-match; end-match;
match udp; match dst-port 9011;
  match over-rate RLB ip-src 1mbit burst 10k; calc-map add RC 3 1; drop; end-match; calc-map add RC 2 1; drop;
end-match; end-match' >/dev/null
send proto=udp,dport=9010,count=50
P=$(( $(v RC 0) )); X=$(( $(v RC 1) ))
check "10/s burst 5: a burst of 50 passes 5-6 ($P passed, $X over)" [ $P -ge 5 -a $P -le 6 -a $((P + X)) -eq 50 ]
sleep 1
send proto=udp,dport=9010,count=5,gap=0.2
P2=$(( $(v RC 0) - P ))
check "10/s: 5 packets 200 ms apart all conform ($P2)" [ $P2 -eq 5 ]
send proto=udp,dport=9011,len=958,count=100
P=$(( $(v RC 2) )); X=$(( $(v RC 3) ))
# 1000-byte frames, 10 KiB burst: about 10, plus what 1 Mbit/s adds while they are sent
check "1mbit burst 10k: 100 x 1000 bytes pass about 10 ($P passed, $X over)" [ $P -ge 9 -a $P -le 16 -a $((P + X)) -eq 100 ]
B $BPFC -i kb0 -c

echo "== count, -K, -V"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'match udp; match dst-port 9020; count USE_P USE_B vlan-id ip-src; drop; end-match; end-match' >/dev/null
send proto=udp,dport=9020,vlan=101,src=100.64.1.20,len=58,count=7 proto=udp,dport=9020,vlan=102,src=100.64.7.3,count=3
check "count: packets per (VLAN, source), decoded with -K" sh -c "$BPFC -m $MAPS -r USE_P -K 'vlan-id ip-src' | grep -qx '101 100.64.1.20 7'"
check "count: bytes (7 x 100-byte frames = 700)" sh -c "$BPFC -m $MAPS -r USE_B -K 'vlan-id ip-src' | grep -qx '101 100.64.1.20 700'"
check "-r -K: a header line names the columns" sh -c "$BPFC -m $MAPS -r USE_P -K 'vlan-id ip-src' | head -1 | grep -qx '# vlan-id ip-src value'"
check "-R -K: joined maps, keys decoded" sh -c "$BPFC -m $MAPS -R USE_P,USE_B -K 'vlan-id ip-src' | grep -qx '102,100.64.7.3 0x3 0xae'"
$BPFC -m $MAPS -w USE_P 'pack vlan-id=200 ip-src=192.0.2.1' 42 >/dev/null
check "-w with a pack key" sh -c "$BPFC -m $MAPS -r USE_P -K 'vlan-id ip-src' | grep -qx '200 192.0.2.1 42'"
$BPFC -m $MAPS -w USE_B 1 'pack dscp=ef ecn=ce' >/dev/null
check "-V decodes a value (dscp ef, ecn ce)" sh -c "$BPFC -m $MAPS -r USE_B -V 'dscp ecn' | grep -qx '0x0000000000000001 ef ce'"
$BPFC -m $MAPS -x USE_P 'pack vlan-id=200 ip-src=192.0.2.1' >/dev/null
check "-x deletes an entry" sh -c "! $BPFC -m $MAPS -r USE_P -K 'vlan-id ip-src' | grep -q '^200 '"
B $BPFC -i kb0 -c

echo "== prefix-map, host, net, port, dscp"
B $BPFC -m $MAPS -i kb0 -d ingress -p 10 'prefix-map ALLOW 100;
match udp; match dst-port 9030;
  if ip-src in ALLOW V; calc-map add PC %V 1; drop; end-if;
  calc-map add PC 0 1; drop;
end-match; end-match;
match udp; match dst-port 9031;
  match host 10.88.0.77; calc-map add PC 10 1; end-match;
  match net 10.89.0.0/16; calc-map add PC 11 1; end-match;
  match port 53; calc-map add PC 12 1; end-match;
  match dscp ef; calc-map add PC 13 1; end-match;
  drop;
end-match; end-match' >/dev/null
$BPFC -m $MAPS -w ALLOW 10.88.0.0/24 1 >/dev/null
$BPFC -m $MAPS -w ALLOW 10.88.0.128/25 2 >/dev/null
send proto=udp,dport=9030,src=10.88.0.5 proto=udp,dport=9030,src=10.88.0.200 proto=udp,dport=9030,src=10.99.0.1
check "prefix-map: the longest prefix wins (/24: $(( $(v PC 1) )), /25: $(( $(v PC 2) )), none: $(( $(v PC 0) )))" [ $(( $(v PC 1) )) -eq 1 -a $(( $(v PC 2) )) -eq 1 -a $(( $(v PC 0) )) -eq 1 ]
check "-r of a prefix map lists prefixes" sh -c "$BPFC -m $MAPS -r ALLOW | grep -qx '10.88.0.128/25 2'"
$BPFC -m $MAPS -x ALLOW 10.88.0.128/25 >/dev/null
send proto=udp,dport=9030,src=10.88.0.200
check "-x removes a prefix: the /24 matches now" [ $(( $(v PC 1) )) -eq 2 ]
send proto=udp,dport=9031,src=10.88.0.1,dst=10.88.0.77 proto=udp,dport=9031,src=10.89.3.4,sport=53 proto=udp,dport=9031,tos=184
check "match host: source or destination ($(( $(v PC 10) )))" [ $(( $(v PC 10) )) -eq 1 ]
check "match net: source or destination ($(( $(v PC 11) )))" [ $(( $(v PC 11) )) -eq 1 ]
check "match port: source or destination ($(( $(v PC 12) )))" [ $(( $(v PC 12) )) -eq 1 ]
check "match dscp ef ($(( $(v PC 13) )))" [ $(( $(v PC 13) )) -eq 1 ]
B $BPFC -i kb0 -c

echo "== XDP"
if B $BPFC -m $MAPS -i kb0 -d xdp 'array-map XK 4; match ip; hash K 64 symmetric ip-src ip-dst ip-proto src-port dst-port; set map XK 1 %K; end-match' >/dev/null 2>&1; then
	send proto=udp,src=10.88.0.2,dst=10.88.0.1,sport=2222,dport=1111
	eqk "XDP: the same key as TC and -H" "$(v XK 1)" "$(H hash 64 symmetric $T1)"
	B $BPFC -i kb0 -d xdp -c
else
	test_skip "XDP key (no generic XDP)"
fi

tests_exit
