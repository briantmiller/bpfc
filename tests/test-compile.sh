#!/bin/bash
# Compile-only tests: no root, no network. Every field and command must
# compile, hex and decimal values must give the same code, and invalid
# programs must fail with a clear message. Commands that create maps need
# root (CAP_BPF) even to compile; that section runs only as root.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
BPFC=$PWD/bpfc
[ -x "$BPFC" ] || { test_fail "compile (build bpfc first: make)"; tests_exit; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; rm -f "$TESTS_FAILED_FILE"' EXIT
cd "$TMP" || exit 1

# ok <name> <program>: compiles (exit 0)
ok() {
	local out
	if out=$("$BPFC" "$2" 2>&1); then test_pass "$1"; else test_fail "$1"; echo "    $2"; echo "$out" | head -3 | sed 's/^/    /'; fi
}
# bad <name> <message substring> <program>: refused (exit != 0, not a crash) with the message
bad() {
	local out rc
	out=$("$BPFC" "$3" 2>&1); rc=$?
	if [ $rc -ne 0 ] && [ $rc -lt 128 ] && [[ "$out" == *"$2"* ]]; then test_pass "$1"
	else test_fail "$1"; echo "    $3"; echo "    want exit 1-127 and '$2'; got exit $rc:"; echo "$out" | head -3 | sed 's/^/    /'; fi
}
# same <name> <program A> <program B>: both compile to identical bytecode
same() {
	if "$BPFC" "$2" >/dev/null 2>&1 && mv output.bpf a.bpf && "$BPFC" "$3" >/dev/null 2>&1 && cmp -s a.bpf output.bpf
	then test_pass "$1"; else test_fail "$1"; echo "    '$2' vs '$3'"; fi
}

MAC=aa:bb:cc:dd:ee:ff
IP4=10.0.0.200
IP6=2001:db8::1

# ---------------- get ----------------
for f in ip-src ip-dst tcp-src tcp-dst udp-src udp-dst tcp-seq tcp-ack tcp-flags tcp-win tcp-hlen \
         l4-off payload-off payload-len flow-key tstamp ip-tos ip-len ip-frag ip-proto ip-ident gre-key \
         gre-proto eth-proto dst-mac src-mac mpls-label mpls-bos vlan-id arp-htype arp-ptype arp-hlen \
         arp-plen arp-oper arp-sha arp-spa arp-tha arp-tpa ip6-src ip6-dst ip6-proto ip6-tclass ip6-flow \
         time random cpu len protocol queue skb-mark skb-hash skb-ingress skb-ifindex; do
	ok "CC-get-$f" "get $f V"
done
ok CC-get-bytes          "get bytes 14 2 V"
ok CC-get-bytes-var      "decl O 4; set val O 14; get bytes %O 4 V"
ok CC-get-skb-cb         "get skb-cb 0 V"
ok CC-get-flow-key-rev   "get flow-key V reverse"
ok CC-get-flow-key-sym   "get flow-key V symmetric"

# ---------------- set: constants, then variables ----------------
declare -A SETVAL=( [dst-mac]=$MAC [src-mac]=$MAC [arp-sha]=$MAC [arp-tha]=$MAC [ip-src]=$IP4 [ip-dst]=$IP4
	[arp-spa]=$IP4 [arp-tpa]=$IP4 [ip6-src]=$IP6 [ip6-dst]=$IP6 [mpls-bos]=1 )
declare -A VARSIZE=( [dst-mac]=8 [src-mac]=8 [arp-sha]=8 [arp-tha]=8 [ip6-src]=16 [ip6-dst]=16 [tstamp]=8 )
for f in tstamp dst-mac src-mac eth-proto ip-src ip-dst ip-tos ip-proto ip-len ip-frag tcp-src tcp-dst \
         udp-src udp-dst vlan-id mpls-label mpls-bos queue arp-htype arp-ptype arp-hlen arp-plen arp-oper \
         arp-sha arp-tha arp-spa arp-tpa ip6-src ip6-dst ip6-proto ip6-tclass ip6-flow icmp-type len \
         skb-mark skb-hash protocol; do
	ok "CC-set-$f"     "set $f ${SETVAL[$f]:-5}"
	ok "CC-set-$f-var" "decl V ${VARSIZE[$f]:-4}; set $f %V"
done
ok CC-set-bytes      "set bytes 14 2 5"
ok CC-set-bytes-8    "set bytes 14 8 0x1122334455667788"
ok CC-set-skb-cb     "set skb-cb 4 5"
ok CC-set-val        "decl V 4; set val V 5"
ok CC-set-val-var    "decl V 4; decl W 4; set val V %W"

# ---------------- match: constants, then variables ----------------
for f in src-mac dst-mac eth-proto vlan-id mpls-label mpls-bos ip-proto ip-tos ip-frag ip-frag-off ip-len \
         ip-src ip-dst tcp-src udp-src tcp-dst udp-dst gre-key gre-proto arp-htype arp-ptype arp-hlen \
         arp-plen arp-oper arp-sha arp-tha arp-spa arp-tpa ip6-src ip6-dst ip6-proto ip6-tclass ip6-flow \
         icmp-type skb-mark skb-hash skb-ifindex skb-ingress len protocol; do
	ok "CC-match-$f"     "match $f ${SETVAL[$f]:-5}"
	ok "CC-match-$f-var" "decl V ${VARSIZE[$f]:-4}; match $f %V"
done
for s in ip ip6 arp mpls icmp gre tcp udp igmp ospf pim esp rsvp l2tp ip-df ip-ndf ip-mf vlan qinq; do
	ok "CC-match-$s" "match $s"
done
ok CC-match-tcp-flags     "match tcp-flags SYN"
ok CC-match-cidr          "match ip-dst 10.0.0.0/8"
ok CC-match-dotted-mask   "match ip-dst 10.0.0.0/255.0.0.0"
ok CC-match-port-range    "match tcp-dst 80-90"
ok CC-match-vlan-range    "match vlan-id 10-20"
ok CC-match-ip6-prefix    "match ip6-dst 2001:db8::/32"
ok CC-if-alias            "decl X 4; if val X eq 1; drop; end-if"
for op in lt gt le ge eq ne seq-lt seq-le seq-gt seq-ge; do
	ok "CC-match-val-$op" "decl X 4; decl Y 4; match val X $op %Y; drop; end-match; match val X $op 5"
done

# ---------------- calc ----------------
for op in add sub mul div and or xor lsh rsh mod; do
	ok "CC-calc-$op"     "decl V 4; calc $op V 3"
	ok "CC-calc-$op-var" "decl V 4; decl W 4; calc $op V %W"
done
ok CC-calc-not   "decl V 4; calc not V"
ok CC-calc-bswap "decl V 4; calc bswap V 32"
ok CC-calc-hton  "decl V 4; calc hton V 16"
ok CC-calc-ntoh  "decl V 8; calc ntoh V 64"

# ---------------- terminals and control flow ----------------
for c in drop continue accept reclassify "redirect lo" "redirect lo ingress" "redirect-neigh lo"; do
	ok "CC-term-${c// /-}" "match tcp; $c"
done
ok CC-else-terminal      "decl X 4; if val X eq 1; drop; else; continue; end-if"
ok CC-else-plain         "decl X 4; if val X eq 1; set ip-tos 1; else; set ip-tos 2; end-if"
ok CC-nested             "match ip; match tcp; match tcp-dst 23; drop; end-match; end-match; end-match"
ok CC-goto-label         "match tcp; goto L; end-match; drop; label L"
ok CC-loop               "decl N 4; set val N 3; start-loop; calc sub N 1; loop N"
ok CC-loop-reg           "set-reg-loop 3; start-loop; dec-reg-loop; loop-reg"
ok CC-dec-reg-loop-n     "set-reg-loop 6; start-loop; dec-reg-loop 2; loop-reg"
ok CC-free-reuse         "decl A 4; free A; decl B 4"
ok CC-decl-16            "decl V 16; get ip6-dst V; set ip6-src %V"

# ---------------- packet editing and other commands ----------------
ok CC-push-vlan          "push-vlan 10"
ok CC-push-vlan-prio     "push-vlan 10 3"
ok CC-pop-vlan           "pop-vlan"
ok CC-push-qinq          "push-qinq 10 20 1 2"
ok CC-push-eth           "push-eth $MAC 11:22:33:44:55:66"
ok CC-pop-eth            "pop-eth"
ok CC-encap-gre          "encap-gre ip-src 1.1.1.1 ip-dst 2.2.2.2 key 5"
ok CC-decap-gre          "decap-gre"
ok CC-encap-mpls         "encap-mpls label 16 bos 1"
ok CC-decap-mpls         "decap-mpls"
ok CC-add-head-bytes     "add-head-bytes 4"
ok CC-add-bytes          "add-bytes 42 8"
ok CC-add-l2-bytes       "add-l2-bytes 4"
ok CC-insert-l2          "insert-l2 8 0x88b5"
ok CC-strip-l2           "strip-l2 8 0x0800"
ok CC-recalc-tcp-csum    "recalc-tcp-csum"
ok CC-recalc-udp-csum    "recalc-udp-csum 14 1500"
ok CC-calc-csum          "calc-csum tcp C"
ok CC-fill-bytes         "fill-bytes 54 4 1"
ok CC-tcp-option         "tcp-option 2 O L"
ok CC-debug-log          "debug-log hello"
ok CC-fib-lookup         "fib-lookup 10.0.0.1"
ok CC-fib-lookup-var     "get ip-dst D; fib-lookup %D"
ok CC-clone              "clone lo"
ok CC-46-variables       "repeat 46 as I; decl V\$I 4; end-repeat"

# ---------------- hex and decimal give the same code ----------------
same CC-hex-ip-tos       "set ip-tos 0x10"            "set ip-tos 16"
same CC-hex-ip-proto     "match ip-proto 0x11"        "match ip-proto 17"
same CC-hex-tcp-dst      "set tcp-dst 0x50"           "set tcp-dst 80"
same CC-hex-port-range   "match tcp-dst 0x50-0x5A"    "match tcp-dst 80-90"
same CC-hex-eth-proto    "set eth-proto 0x0800"       "set eth-proto 2048"
same CC-hex-vlan         "push-vlan 0x64 3"           "push-vlan 100 3"
same CC-hex-icmp-type    "set icmp-type 0x08"         "set icmp-type 8"
same CC-hex-calc         "decl V 4; calc add V 0x10"  "decl V 4; calc add V 16"

# ---------------- invalid programs ----------------
bad CC-err-unknown-cmd      "Invalid instruction bogus"           "bogus"
bad CC-err-unknown-get      "Invalid get instruction bogus"       "get bogus V"
bad CC-err-unknown-set      "Invalid set instruction bogus"       "set bogus 5"
bad CC-err-unknown-match    "Invalid match instruction bogus"     "match bogus 5"
bad CC-err-decl-size        "decl size must be 1, 2, 4, 8 or 16"  "decl V 3"
bad CC-err-decl-too-big     "at most 16"                          "decl V 32"
bad CC-err-undefined-var    "Undefined variable 'NOPE'"           "set val NOPE 5"
bad CC-err-calc-op          "Invalid math instruction frob"       "decl V 4; calc frob V 5"
bad CC-err-match-val-op     "Invalid match val operation zz"      "decl V 4; if val V zz 1; drop; end-if"
bad CC-err-after-terminal   "last command was terminal"           "match tcp; continue; set ip-tos 1"
bad CC-err-terminal-twice   "last command was terminal"           "match tcp; drop; drop"
bad CC-err-stray-end-match  "end-match without an open match"     "end-match"
bad CC-err-stray-end-if     "end-if without an open match"        "end-if"
bad CC-err-stray-else       "else without an open match"          "else"
bad CC-err-extra-end-match  "end-match without an open match"     "match tcp; end-match; end-match"
bad CC-err-open-loop        "start-loop without a matching loop"  "start-loop"
bad CC-err-loop-no-start    "without a preceding 'start-loop'"    "decl N 4; loop N"
bad CC-err-goto-undefined   "Undefined goto target label 'NOWHERE'" "goto NOWHERE"
bad CC-err-label-twice      "Duplicate label 'A'"                 "label A; label A"
bad CC-err-ip-octet         "must be an IPv4 address"             "match ip-src 10.0.0.300"
bad CC-err-ip-short         "must be an IPv4 address"             "match ip-src 10.0.0"
bad CC-err-ip-prefix        "must be an IPv4 address"             "match ip-src 10.0.0.1/33"
bad CC-err-ip-word          "must be an IPv4 address"             "set ip-dst banana"
bad CC-err-ip-prefix-in-set "must be an IPv4 address"             "set ip-dst 10.0.0.0/8"
bad CC-err-mac-short        "must be a MAC address"               "set dst-mac aa:bb:cc"
bad CC-err-mac-hex          "must be a MAC address"               "match src-mac zz:bb:cc:dd:ee:ff"
bad CC-err-ip6              "must be an IPv6 address"             "match ip6-dst 2001:db8::zz"
bad CC-err-ip6-prefix       "must be an IPv6 address"             "match ip6-dst 2001:db8::/200"
bad CC-err-port-big         "from 0 to 65535"                     "set tcp-dst 70000"
bad CC-err-port-range-order "from 0 to 65535"                     "match tcp-dst 90-80"
bad CC-err-port-range-set   "from 0 to 65535"                     "set tcp-dst 80-90"
bad CC-err-tos-big          "from 0 to 255"                       "set ip-tos 300"
bad CC-err-vlan-big         "from 0 to 4095"                      "match vlan-id 5000"
bad CC-err-mpls-bos         "from 0 to 1"                         "set mpls-bos 2"
bad CC-err-not-a-number     "must be a number"                    "set ip-tos ten"
bad CC-err-bad-hex          "is not a valid number"               "set ip-tos 0xZZ"
bad CC-err-push-vlan-id     "push-vlan <vlan-id 0-4095>"          "push-vlan 5000"
bad CC-err-push-vlan-prio   "push-vlan <vlan-id 0-4095>"          "push-vlan 10 9"
bad CC-err-push-qinq        "usage: push-qinq"                    "push-qinq 10"
bad CC-err-push-eth         "usage: push-eth"                     "push-eth aa:bb 11:22:33:44:55:66"
bad CC-err-encap-gre        "usage: encap-gre"                    "encap-gre ip-src 1.1.1.1"
bad CC-err-encap-gre-ip     "usage: encap-gre"                    "encap-gre ip-src 1.1.1 ip-dst 2.2.2.2 key 5"
bad CC-err-redirect-noarg   "redirect needs an argument"          "redirect"
bad CC-err-redirect-neigh   "redirect-neigh needs an argument"    "redirect-neigh"
bad CC-err-clone-noarg      "clone needs an argument"             "clone"
bad CC-err-debug-log-noarg  "debug-log needs an argument"         "debug-log"
bad CC-err-ip-frag-noarg    "usage: ip-frag"                      "ip-frag"
bad CC-err-unknown-iface    "Iface 'nosuchif0' not found"         "redirect nosuchif0"
bad CC-err-unknown-iface-2  "Iface 'nosuchif0' not found"         "clone nosuchif0"
bad CC-err-fib-ip           "not a valid IPv4 address"            "fib-lookup banana"
bad CC-err-ip-frag-small    "ip-frag needs a fragment size"       "ip-frag 20 3000"
bad CC-err-ip6-var-size     "needs a 16-byte variable"            "decl V 4; match ip6-dst %V"
bad CC-err-insert-l2        "insert-l2 length must be 1-64"       "insert-l2 100"
bad CC-err-strip-l2         "strip-l2 length must be a multiple of 4" "strip-l2 3 0x800"
bad CC-err-fill-bytes       "fill-bytes length must be 1-64"      "fill-bytes 14 100 0"
bad CC-err-get-bytes-len    "get bytes length must be 1, 2, 4, or 8" "get bytes 14 3 V"
bad CC-err-skb-cb-index     "skb-cb index must be between 0 and 4" "set skb-cb 7 5"
bad CC-err-too-many-vars    "no stack left for variable"          "repeat 49 as I; decl V\$I 8; end-repeat"
bad CC-err-too-many-words   "more than 16 words"                  "debug-log a b c d e f g h i j k l m n o p q"

# ---------------- device type and kind ----------------
# known while compiling: from -i, or -s IFTYPE=/IFKIND= without an interface
okx() { local n=$1; shift; local out; if out=$("$BPFC" "$@" 2>&1); then test_pass "$n"; else test_fail "$n"; echo "$out" | head -3 | sed 's/^/    /'; fi; }
D="-s IFTYPE=778 -s IFKIND=gre"
okx CC-dev-match-type       $D "match dev-type 778; drop"
okx CC-dev-match-kind       $D "match dev-kind gre; drop"
okx CC-dev-if-else          $D "if dev-kind veth; drop; else; accept; end-if"
okx CC-dev-get-type         $D "get dev-type T; set ip-tos %T"
okx CC-dev-match-var        $D "decl T 4; set val T 778; match dev-type %T; drop"
out=$("$BPFC" -s IFTYPE=778 -s IFKIND=gre -E 'when $IFKIND == gre; drop; otherwise; accept; end-when; when $IFTYPE != 1; continue; end-when')
check CC-dev-when-text      [ "$out" == "$(printf 'drop;\ncontinue;\n')" ]
"$BPFC" $D "match dev-kind gre; set ip-tos 1" >/dev/null && mv output.bpf a.bpf
"$BPFC" $D "set ip-tos 1" >/dev/null
check CC-dev-true-costs-nothing cmp -s a.bpf output.bpf
out=$("$BPFC" -i lo -E 'debug-log $IFNAME $IFINDEX $IFTYPE $IFKIND' 2>&1)
check CC-dev-lo-constants   [ "$out" == "debug-log lo 1 772 lo;" ]
out=$("$BPFC" -i lo -s IFKIND=gre -E 'debug-log $IFKIND' 2>&1)
check CC-dev-s-wins         [ "$out" == "debug-log gre;" ]
bad CC-err-dev-no-iface     "dev-type needs the interface"        "match dev-type 1"
bad CC-err-dev-kind-no-iface "dev-kind needs the interface"       "match dev-kind gre"
bad CC-err-dev-type-value   "must be a number from 0 to 65535"    "match dev-type gre"
bad CC-err-dev-set          "Invalid set instruction dev-type"    "set dev-type 1"

# ---------------- commands that create maps (root) ----------------
if [ "$(id -u)" -ne 0 ]; then
	test_skip "CC-maps (creating maps needs root)"
	tests_exit
fi
M="-m $TMP"
for p in "set map M 1 5" "get map M 1 V" "calc-map add M 1 1" "calc-map xchg M 1 5 OLD" "array-map A 8; set map A 3 1" \
         "buffer-map B 512; save-packet B 64" "shared-buffer-map S 4 512; save-packet-keyed S 1 64; load-packet-keyed S 1 64" \
         "shared-buffer-map S 4 512; xor-packet-keyed S 0 64 42 0; zero-buffer-keyed S 0 64" "del-bytes 42 8" "del-l2-bytes 4" \
         "ip-frag 500 3000" "ip-defrag"; do
	n=$(echo "$p" | awk '{print $1}')
	if out=$("$BPFC" $M "$p" 2>&1) && [[ "$out" == *Compiled* ]]; then test_pass "CC-map-$n ($p)"
	else test_fail "CC-map-$n ($p)"; echo "$out" | grep -v -i pin | head -3 | sed 's/^/    /'; fi
done

tests_exit
