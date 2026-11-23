#!/bin/bash
# Compile-only tests: no root, no network. Every field and command must
# compile, hex and decimal values must give the same code, and invalid
# programs must fail with a clear message. Commands that create maps need
# CAP_BPF (or CAP_SYS_ADMIN) even to compile: that section runs only where
# a test map can be created, so it skips when not run as root and in
# containers without BPF access (rootless ones, or root without the
# capability), as in a package build.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
BPFC=$PWD/bpfc
[ -x "$BPFC" ] || { test_fail "compile (build bpfc first: make)"; tests_exit; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; rm -f "$TESTS_FAILED_FILE"' EXIT
cd "$TMP" || exit 1

# ok <name> <program>: compiles (exit 0)
# With XDP_SWEEP_IF=<interface> (test-xdp.sh) each program is instead loaded
# as an XDP program there: it must load, or be refused at compile time with
# the "not available in XDP programs" error, never by the kernel verifier.
ok() {
	local out
	if [ -n "$XDP_SWEEP_IF" ]; then
		out=$("$BPFC" $XDP_SWEEP_OPTS -i "$XDP_SWEEP_IF" -d xdp "$2" 2>&1)
		local rc=$?
		if [ $rc -eq 0 ]; then echo "XDP-LOADS $1"; test_pass "XDP-$1"
		elif [[ "$out" == *"not available in XDP programs"* ]]; then echo "XDP-REFUSED $1"; test_pass "XDP-$1"
		elif [[ "$out" == *"VERIFIER"* || $rc -ge 128 ]]; then test_fail "XDP-$1 (kernel rejected it)"; echo "    $2"; echo "$out" | grep -v "^ *$" | tail -4 | sed 's/^/    /'
		else echo "XDP-OTHER $1: $(echo "$out" | head -1)"; test_pass "XDP-$1"; fi
		return
	fi
	if out=$("$BPFC" "$2" 2>&1); then test_pass "$1"; else test_fail "$1"; echo "    $2"; echo "$out" | head -3 | sed 's/^/    /'; fi
}
# bad <name> <message substring> <program>: refused (exit != 0, not a crash) with the message
bad() {
	local out rc
	[ -n "$XDP_SWEEP_IF" ] && return
	out=$("$BPFC" "$3" 2>&1); rc=$?
	if [ $rc -ne 0 ] && [ $rc -lt 128 ] && [[ "$out" == *"$2"* ]]; then test_pass "$1"
	else test_fail "$1"; echo "    $3"; echo "    want exit 1-127 and '$2'; got exit $rc:"; echo "$out" | head -3 | sed 's/^/    /'; fi
}
# same <name> <program A> <program B>: both compile to identical bytecode
same() {
	[ -n "$XDP_SWEEP_IF" ] && return
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
         time random cpu len protocol queue skb-mark skb-hash skb-priority gso-segs skb-ingress skb-ifindex; do
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
         skb-mark skb-hash skb-priority protocol; do
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
         icmp-type skb-mark skb-hash skb-priority gso-segs skb-ifindex skb-ingress len protocol; do
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
ok CC-remove-l2          "remove-l2 28 0x88b5"
ok CC-remove-l2-noproto  "remove-l2 12"
ok CC-recalc-tcp-csum    "recalc-tcp-csum"
ok CC-recalc-udp-csum    "recalc-udp-csum 14 1500"
ok CC-calc-csum          "calc-csum tcp C"
ok CC-fill-bytes         "fill-bytes 54 4 1"
ok CC-tcp-option         "tcp-option 2 O L"
ok CC-debug-log          "debug-log hello"
ok CC-fib-lookup         "fib-lookup 10.0.0.1"
ok CC-fib-lookup-var     "get ip-dst D; fib-lookup %D"
ok CC-fib-lookup-ports   "decl S 4; set val S 7; get ip-dst D; fib-lookup ports %S %D"
ok CC-fib-lookup-flow-ports "decl S 4; set val S 7; get ip-dst D; fib-lookup flow ports %S %D"
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
bad CC-err-fib-ports        "needs a %VAR"                        "fib-lookup ports 7 10.0.0.1"
bad CC-err-ip-frag-small    "ip-frag needs a fragment size"       "ip-frag 20 3000"
bad CC-err-ip6-var-size     "needs a 16-byte variable"            "decl V 4; match ip6-dst %V"
bad CC-err-insert-l2        "insert-l2 length must be 1-64"       "insert-l2 100"
bad CC-err-remove-l2        "remove-l2 length must be 1-64"       "remove-l2 0"
bad CC-err-strip-l2         "strip-l2 length must be a multiple of 4" "strip-l2 3 0x800"
bad CC-err-fill-bytes       "fill-bytes length must be 1-64"      "fill-bytes 14 100 0"
bad CC-err-get-bytes-len    "get bytes length must be 1, 2, 4, or 8" "get bytes 14 3 V"
bad CC-err-skb-cb-index     "skb-cb index must be between 0 and 4" "set skb-cb 7 5"
bad CC-err-too-many-vars    "no stack left for variable"          "repeat 49 as I; decl V\$I 8; end-repeat"
bad CC-err-too-many-words   "more than 32 words"                  "debug-log a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F"

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

# ---------------- devices without an Ethernet header (L3OFF 0) ----------------
R="-s L3OFF=0"
okx CC-raw-shorthands      $R "match ip; match tcp; match tcp-dst 80; match tcp-flags SYN; drop"
okx CC-raw-ip6             $R "match ip6; match ip6-dst fd00::2; set ip6-tclass 3"
okx CC-raw-ip-fields       $R "match udp; get ip-src S; set ip-dst 10.0.0.9; set ip-tos 4; set udp-dst 53; recalc-udp-csum"
okx CC-raw-l4-family       $R "match tcp; get l4-off O; get payload-len P; get tcp-flags F; tcp-option 2 MO ML; get flow-key K"
okx CC-raw-icmp-gre        $R "match icmp; set icmp-type 0; end-match; match gre; get gre-key K"
okx CC-raw-from-iftype     -s IFTYPE=778 "match ip; match ip-proto 47; drop"
out=$("$BPFC" -s IFTYPE=65534 -E 'debug-log $L3OFF' 2>&1); check CC-raw-l3off-tun [ "$out" == "debug-log 0;" ]
out=$("$BPFC" -s IFTYPE=1 -E 'debug-log $L3OFF' 2>&1);     check CC-raw-l3off-eth [ "$out" == "debug-log 14;" ]
out=$("$BPFC" -E 'debug-log $L3OFF' 2>&1);                 check CC-raw-l3off-default [ "$out" == "debug-log 14;" ]
"$BPFC" "match tcp; match tcp-dst 80; set ip-tos 4" >/dev/null && mv output.bpf a.bpf
"$BPFC" -s L3OFF=14 "match tcp; match tcp-dst 80; set ip-tos 4" >/dev/null
check CC-raw-eth-unchanged cmp -s a.bpf output.bpf
"$BPFC" $R "match tcp; match tcp-dst 80; set ip-tos 4" >/dev/null
check CC-raw-differs       eval '! cmp -s a.bpf output.bpf'
badx() { local n=$1 msg=$2; shift 2; local out; out=$("$BPFC" "$@" 2>&1); local rc=$?
	if [ $rc -ne 0 ] && [ $rc -lt 128 ] && [[ "$out" == *"$msg"* ]]; then test_pass "$n"; else test_fail "$n"; echo "$out" | head -2 | sed 's/^/    /'; fi; }
for c in "match arp" "match mpls" "match vlan" "match eth-proto 0x800" "get src-mac M" "set dst-mac 02:00:00:00:00:01" \
         "get arp-spa A" "set mpls-label 5" "push-eth 02:00:00:00:00:01 02:00:00:00:00:02" "pop-eth" "push-vlan 5" \
         "encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 5" "decap-gre" "encap-mpls label 16 bos 1" "decap-mpls" "strip-l2 4 0x0800" \
         "insert-l2 4" "remove-l2 4" "fib-lookup 10.0.0.1" "ip-frag 500 1500"; do
	badx "CC-raw-err-${c%% *}-$(echo "$c" | awk '{print $2}')" "needs an Ethernet header" $R "$c"
done
badx CC-raw-err-l3off-value "L3OFF must be 14" -s L3OFF=4 "continue"

# ---------------- coverage: options, verbose output, help ----------------
# okx/badx (above) run bpfc with options; none of these is swept as XDP.
okv() { local n=$1 want=$2; shift 2; local out; out=$("$BPFC" "$@" 2>&1)
	if [ $? -eq 0 ] && [[ "$out" == *"$want"* ]]; then test_pass "$n"; else test_fail "$n"; echo "$out" | tail -3 | sed 's/^/    /'; fi; }
okv CC-verbose-match  "END-MATCH"      -v "decl X 4; match ip-proto 6; set val X 1; else; set val X 2; end-match; match tcp; drop; else; accept; end-match"
okv CC-verbose-if     "END-MATCH jump from"         -v "decl X 4; if val X eq 1; drop; else; continue; end-if"
okv CC-verbose-loop   "LOOP EVAL"     -v "decl N 4; set val N 3; start-loop; calc sub N 1; loop N"
okv CC-verbose-reg    "Loop target registered"           -v "set-reg-loop 3; start-loop; dec-reg-loop; loop-reg"
okv CC-verbose-goto   "Resolved forward GOTO" -v "match tcp; goto L; end-match; drop; label L"
okv CC-verbose-back   "Default continue" -v "decl N 4; set val N 2; label B; calc sub N 1; if val N ne 0; goto B; end-if"
okv CC-help           "Usage:"         -h
okv CC-help-long      "Terminal Commands" --help
# Every command (the names a macro may not take, which are the commands)
# is in -h, except reserved words that are not commands yet.
H=$("$BPFC" -h | sed 's/zero-buffer\[-keyed\]/zero-buffer zero-buffer-keyed/')
missing=
for c in $(sed -n '/^static const char \*pp_reserved\[\] = {/,/};/p' "$(dirname "$BPFC")/bpfc.c" | grep -o '"[^"]*"' | tr -d '"'); do
	case $c in del-head-bytes|pop-mac-bytes|push-mac-bytes|pop-net-bytes|push-net-bytes|fib-lookup6|otherwise|UNIQUE) continue ;; esac
	grep -qE "(^|[[:space:]\"])$c([[:space:]<[]|$)" <<< "$H" || missing="$missing $c"
done
check "CC-help-lists-every-command${missing:+ (missing:$missing)}" [ -z "$missing" ]
badx CC-err-opt-noarg      "option -i requires an argument" -i
badx CC-err-priority       "priority must be between 0 and 65535" -i lo -p 70000 "continue"
badx CC-err-clear-no-iface "-c and -D require -i"         -c
badx CC-err-del-no-prio    "-D requires -p"               -D -i lo
echo continue > prog.bpfc
badx CC-err-frontend-name  "-F needs a frontend name"     -F 'BAD!' -f prog.bpfc
badx CC-err-frontend-stdin "-F acl with -f -"             -F acl -f -
badx CC-err-many-L         "at most"                      $(for i in $(seq 1 20); do printf -- '-L d%d ' $i; done) "continue"
badx CC-err-no-program     "Usage:"

# ---------------- coverage: commands and operand forms ----------------
ok CC-get-l4-proto        "get l4-proto V"
ok CC-get-frag-off        "get frag-off V"
bad CC-err-get-l4-proto   "get l4-proto <VAR>"           "get l4-proto V W"
# 8-byte variables (64-bit loads and stores) and variables as operands
ok CC-get-tcp-seq-8 "decl V 8; get tcp-seq V"
for f in ip-src ip-dst skb-mark ip-tos tcp-dst; do
	ok "CC-get-$f-8"   "decl V 8; get $f V"
	ok "CC-set-$f-8"   "decl V 8; set $f %V"
	ok "CC-match-$f-8" "decl V 8; match $f %V"
done
ok CC-get-bytes-8         "decl V 8; get bytes 14 8 V; set bytes 14 8 %V"
ok CC-get-bytes-var-8     "decl O 4; set val O 14; decl V 8; get bytes %O 8 V"
ok CC-set-bytes-var-off   "decl O 4; set val O 14; decl V 4; set bytes %O 4 %V"
ok CC-match-port-range-8  "decl V 8; set val V 80; match tcp-dst %V"
ok CC-set-val-8           "decl V 8; decl W 8; set val V %W; set val W 5"
ok CC-set-vlan-id-8       "decl V 8; set vlan-id %V"
ok CC-push-vlan-vars      "decl I 4; decl P 4; set val I 100; set val P 3; push-vlan %I %P"
ok CC-push-vlan-var-id    "decl I 4; push-vlan %I"
ok CC-push-eth-vars       "get src-mac S; get dst-mac D; push-eth %S %D"
ok CC-push-eth-var-src    "get src-mac S; push-eth 02:00:00:00:00:01 %S"
bad CC-err-push-eth-size  "must be an 8-byte variable"   "decl V 4; push-eth %V 02:00:00:00:00:01"
bad CC-err-push-eth-undef "must be an 8-byte variable"   "push-eth 02:00:00:00:00:01 %NOPE"
ok CC-add-head-bytes-var  "decl L 4; set val L 4; add-head-bytes %L"
ok CC-set-reg-loop-var    "decl N 4; set val N 3; set-reg-loop %N; start-loop; dec-reg-loop %N; loop-reg"
ok CC-fib-src-var         "decl S 4; get ip-src S; fib-lookup src %S"
ok CC-fib-src-ip          "fib-lookup src 10.0.0.1 10.0.0.2"
ok CC-fib-src-flag        "fib-lookup src"
ok CC-fib-iface           "fib-lookup iface lo"
ok CC-fib-iface-var       "decl I 4; set val I 1; fib-lookup iface %I"
ok CC-fib-options         "fib-lookup output skip-neigh tbid 100"
bad CC-err-fib-var-size   "fib-lookup requires a 4-byte IPv4 variable" "decl D 8; fib-lookup %D"
bad CC-err-fib-src        "is not a valid IPv4 address"  "fib-lookup src 1.2.3"
bad CC-err-fib-tbid       "tbid needs a table number"    "fib-lookup tbid x"
bad CC-err-fib-mark       "mark is not supported yet"    "fib-lookup mark"
bad CC-err-fib-lookup6    "fib-lookup6 is not available yet" "fib-lookup6 2001:db8::1"
ok CC-set-dscp-var        "decl V 1; set val V 46; set dscp %V"
ok CC-set-ecn-var         "decl V 4; set ecn %V"
ok CC-match-host-var      "decl V 4; get ip-dst V; match host %V"
ok CC-match-host6         "match host 2001:db8::1"
ok CC-match-host6-var     "decl V 16; get ip6-src V; match host %V"
ok CC-match-port-var      "decl V 4; set val V 53; match port %V"
ok CC-match-tcp-flags-all "match tcp-flags fin syn rst psh ack urg"
bad CC-err-tcp-flag       "unknown flag 'BOGUS'"         "match tcp-flags SYN BOGUS"
bad CC-err-match-port     "a port 0-65535"               "match port 70000"
bad CC-err-set-dscp       "a DSCP name"                  "set dscp bogus"
bad CC-err-set-ecn        "not-ect, ect1, ect0, ce"      "set ecn bogus"
bad CC-err-match-var-op   "Invalid match val operation zz" "decl V 4; match V zz 1"
bad CC-err-match-val-op2  "Invalid match val operation zz" "decl V 4; match val V zz 1"
bad CC-err-set-bytes-len  "set bytes length must be 1, 2, 4, or 8" "set bytes 14 3 5"
bad CC-err-set-bytes-vlen "set bytes length must be 1, 2, 4, or 8" "decl V 4; set bytes 14 3 %V"
bad CC-err-get-bytes-vlen "get bytes length must be 1, 2, 4, or 8" "decl O 4; get bytes %O 3 V"
bad CC-err-loop-reg       "without a preceding 'start-loop'" "loop-reg"
bad CC-err-else-args      "Usage: else"                  "else 5"
bad CC-err-get-skb-cb     "skb-cb index must be between 0 and 4" "get skb-cb 9 V"
bad CC-err-match-skb-cb   "skb-cb index must be between 0 and 4" "match skb-cb 9 5"
bad CC-err-too-many-insns "program exceeds"              "repeat 3000; set ip-tos 1; end-repeat"
bad CC-err-too-many-gotos "unresolved gotos exceeded"    "repeat 1100; goto X; end-repeat; label X"

# ---------------- coverage: keys, -H and the preprocessor ----------------
ok CC-hash-bytes-var      "decl O 4; set val O 14; hash K 32 bytes %O 4"
ok CC-pack-var            "decl V 4; pack K %V"
ok CC-pack-ip-len         "pack K ip-len"
ok CC-pack-ip6-tclass     "pack K ip6-tclass"
ok CC-pack-var-bits       "decl V 4; pack K %V:16 ip-len"
ok CC-hash-seed-var       "decl S 4; hash K 32 seed %S ip-src"
bad CC-err-hash-families  "IPv4 or IPv6 fields, not both" "hash K 32 ip-len ip6-tclass"
bad CC-err-hash-prefix    "only ip-src, ip-dst, ip6-src and ip6-dst take a /prefix" "hash K 32 tcp-dst/8"
bad CC-err-hash-buckets   "buckets needs a count"        "hash K buckets x ip-src"
bad CC-err-hash-usage     "usage: hash <VAR>"            "hash K"
bad CC-err-pack-usage     "usage: pack <VAR>"            "pack K"
okv CC-H-bytes            "0x"                           -H "pack bytes:14:2=5"
okv CC-H-prefix           "0x"                           -H "pack ip-src/8=10.0.0.0"
badx CC-err-H-form        "write 'hash <bits> [options]" -H "bogus"
badx CC-err-H-novalue     "needs a value"                -H "hash 32 ip-src=10.0.0.1 reverse"
badx CC-err-H-reverse     "reverse: give both"           -H "hash 64 reverse ip-src=10.0.0.1"
badx CC-err-H-addr        "is not an IPv4 address"       -H "pack ip-src=x"
badx CC-err-H-ip6-pack    "a pack holds 64; use hash"    -H "pack ip6-src=::1"
bad CC-err-pp-dollar      "'\$' must be followed by a name" 'set val $ 5'
bad CC-err-pp-const-name  "bad const name '9X'"          "const 9X 5"
bad CC-err-pp-const-twice "const A is already defined"   "const A 1; const A 2"
out=$("$BPFC" -s A=1 -E 'const A 2; debug-log $A' 2>&1)
check CC-pp-s-overrides-const [ "$out" == "debug-log 1;" ]
bad CC-err-pp-expr-short  "expression ends too early"    'debug-log $(1 + )'
bad CC-err-pp-expr-junk   "unexpected '2' in expression" 'debug-log $(1 2)'
bad CC-err-pp-option      "usage: option on-failure keep|remove" "option on-failure maybe"
bad CC-err-pp-repeat-max  "is not 0-4096"                "repeat 100000; continue; end-repeat"
bad CC-err-pp-runaway     "expansion produced more than" "repeat 4096; repeat 4096; set ip-tos 1; end-repeat; end-repeat"
mkdir -p dep && echo 'depends data.txt' > dep/prog.bpfc && : > dep/data.txt
out=$("$BPFC" -M -f dep/prog.bpfc 2>&1)
check CC-pp-depends-relative eval '[[ "$out" == *dep/data.txt* ]]'

# ---------------- commands that create maps ----------------
# Being uid 0 is not enough: in a rootless container (a user namespace) or
# a container without CAP_BPF/CAP_SYS_ADMIN the kernel still refuses
# BPF_MAP_CREATE. Try one map; skip the section only when the kernel refused
# it, so that a bpfc that fails for another reason still fails here.
M="-m $TMP"
if ! probe=$("$BPFC" $M "set map BPFC_PROBE 1 1" 2>&1) || [[ "$probe" != *Compiled* ]]; then
	if [[ "$probe" == *"Failed to create BPF Map"* ]]; then
		why=$(echo "$probe" | sed -n 's/.*Failed to create BPF Map[^:]*: //p' | head -1)
		test_skip "CC-maps (cannot create BPF maps here: ${why:-refused}; needs CAP_BPF, which rootless and unprivileged containers lack)"
		tests_exit
	fi
	test_fail "CC-maps-probe (set map: $(echo "$probe" | head -1))"
fi
for p in "set map M 1 5" "get map M 1 V" "calc-map add M 1 1" "calc-map xchg M 1 5 OLD" "array-map A 8; set map A 3 1" \
         "buffer-map B 512; save-packet B 64" "shared-buffer-map S 4 512; save-packet-keyed S 1 64; load-packet-keyed S 1 64" \
         "shared-buffer-map S 4 512; xor-packet-keyed S 0 64 42 0; zero-buffer-keyed S 0 64" "del-bytes 42 8" "del-l2-bytes 4" \
         "ip-frag 500 3000" "ip-defrag"; do
	n=$(echo "$p" | awk '{print $1}')
	if [ -n "$XDP_SWEEP_IF" ]; then XDP_SWEEP_OPTS=$M ok "CC-map-$n ($p)" "$p"; continue; fi
	if out=$("$BPFC" $M "$p" 2>&1) && [[ "$out" == *Compiled* ]]; then test_pass "CC-map-$n ($p)"
	else test_fail "CC-map-$n ($p)"; echo "$out" | grep -v -i pin | head -3 | sed 's/^/    /'; fi
done

# map commands: forms and errors (coverage)
okm() { local n=$1; shift; local out; if out=$("$BPFC" $M "$@" 2>&1) && [[ "$out" == *Compiled* ]]; then test_pass "$n"; else test_fail "$n"; echo "$out" | grep -v -i pin | head -3 | sed 's/^/    /'; fi; }
badm() { local n=$1 msg=$2; shift 2; local out; out=$("$BPFC" $M "$@" 2>&1); local rc=$?
	if [ $rc -ne 0 ] && [ $rc -lt 128 ] && [[ "$out" == *"$msg"* ]]; then test_pass "$n"; else test_fail "$n"; echo "    want '$msg'; got exit $rc:"; echo "$out" | head -2 | sed 's/^/    /'; fi; }
okm  CC-over-rate-gbit     "match over-rate OR1 ip-src 1gbit burst 1mb; drop"
okm  CC-over-rate-burst-m  "match over-rate OR2 ip-src 10mbit burst 2m; drop"
badm CC-err-seen-usage     "usage: match seen"            "match seen SN ip-src"
badm CC-err-seen-junk      "unexpected 'junk' after the time" "match seen SN ip-src within 5s junk"
badm CC-err-rate-usage     "usage: match over-rate"       "match over-rate OR3 ip-src"
badm CC-err-rate-junk      "unexpected 'junk' after the rate" "match over-rate OR3 ip-src 10mbit junk"
badm CC-err-in-usage       "usage: match <ip-src|ip-dst"  "match ip-src in"
badm CC-err-in-not-prefix  "is not a prefix map"          "match ip-src in NOPE"
okm  CC-in-var             "prefix-map PV 16; decl V 4; get ip-src V; match %V in PV; drop"
okm  CC-in-ip6             "prefix-map PV6 16 ipv6; match ip6-src in PV6; drop"
okm  CC-in-ip6-var         "prefix-map PV6 16 ipv6; decl V 16; get ip6-dst V; match %V in PV6; drop"
badm CC-err-in-ip6-var     "is an IPv4 address"           "prefix-map PV6 16 ipv6; decl V 4; match %V in PV6"
badm CC-err-in-ip6-field   "ip6-src, ip6-dst or a 16-byte %VAR" "prefix-map PV6 16 ipv6; match ip6-flow in PV6"
badm CC-err-in-field       "a %VAR holding an address"    "prefix-map PV 16; match tcp-dst in PV"
badm CC-err-log-bytes      "bytes: a multiple of 8"       "ringbuf-map RB; log RB 1 7"
badm CC-err-ringbuf-usage  "usage: ringbuf-map"           "ringbuf-map"
badm CC-err-ringbuf-args   "usage: ringbuf-map"           "ringbuf-map RB 1 2 3"
badm CC-err-prefix-map     "usage: prefix-map"            "prefix-map"
badm CC-err-prefix-undecl  "declare it first with prefix-map" "prefix NOPE 10.0.0.0/8"
badm CC-err-prefix-ip6     "is not an IPv6 prefix"        "prefix-map PS6 10 ipv6 static; prefix PS6 bogus"
okm  CC-prefix-static      "prefix-map PS4 10 static; prefix PS4 10.0.0.0/8 5; prefix PS4 10.1.0.0/16; match ip-dst in PS4; drop"
okm  CC-prefix-static-ip6  "prefix-map PS6 10 ipv6 static; prefix PS6 2001:db8::/32 3; match ip6-dst in PS6; drop"
badm CC-err-calc-map-op    "calc-map operation must be add, or, and, xor or xchg" "calc-map frob CM 1 1"
badm CC-err-array-entries  "needs 1-16777216 entries"     "array-map AM 0"
badm CC-err-prefix-entries "needs 1-16777216 entries"     "prefix-map PE 0"
badm CC-err-buffer-size    "value size must be 16-65536"  "buffer-map BS 8"

# hash-map: the size of a default (LRU hash) map; pinned maps need a bpffs
mkdir -p "$TMP/bpf"
if ! mount -t bpf bpf "$TMP/bpf" 2>/dev/null; then
	test_skip "CC-hash-map (cannot mount bpffs)"
	tests_exit
fi
trap 'umount "$TMP/bpf" 2>/dev/null; rm -rf "$TMP"; rm -f "$TESTS_FAILED_FILE"' EXIT
M="-m $TMP/bpf"
hm() { "$BPFC" $M "$@" 2>&1; }
check CC-hash-map            eval 'hm "hash-map HM 8; set map HM 1 5" | grep -q Compiled'
check CC-hash-map-resize     eval 'hm "hash-map HM 16; set map HM 1 5" | grep -q "is pinned with 8 entries, declared with 16; replacing"'
check CC-hash-map-same       eval '! hm "hash-map HM 16; set map HM 1 5" | grep -q Warning'
check CC-hash-map-undeclared eval 'hm "set map HM 2 6" | grep -q Compiled && ! hm "hash-map HM 16; get map HM 2 V" | grep -q Warning'
check CC-hash-map-after-use  eval 'hm "set map HM2 1 1; hash-map HM2 32" | grep -q "must come before"'
check CC-hash-map-range      eval 'hm "hash-map HM3 0" | grep -q "needs 1-16777216 entries"'
check CC-hash-map-array      eval 'hm "array-map HA 4; set map HA 1 1" >/dev/null && hm "hash-map HA 4; set map HA 1 1" | grep -q "pinned as another kind of map"'

# Pinned maps of another kind or size are replaced; maps of other value
# sizes cannot be read or written with -r/-w; -K/-V layouts (coverage)
check CC-pin-prefix-v6       eval 'hm "prefix-map PX 16; match ip-src in PX; drop" | grep -q Compiled && hm "prefix-map PX 16 ipv6; match ip6-src in PX; drop" | grep -q "is pinned with another size; replacing"'
check CC-pin-prefix-size     eval 'hm "prefix-map PX 32 ipv6; match ip6-src in PX; drop" | grep -q "replacing the pinned map"'
check CC-pin-prefix-same     eval '! hm "prefix-map PX 32 ipv6; match ip6-src in PX; drop" | grep -q Warning'
check CC-pin-prefix-late     eval 'hm "array-map AX 4; prefix-map AX 16" | grep -q "must come before the map is first used"'
check CC-pin-ringbuf-size    eval 'hm "ringbuf-map RX 4096; log RX 1" | grep -q Compiled && hm "ringbuf-map RX 8192; log RX 1" | grep -q "pinned as another kind of map or size; replacing"'
check CC-pin-ringbuf-kind    eval 'hm "array-map RY 4; ringbuf-map RY" | grep -q "is not a ring buffer"'
check CC-pin-buffer-size     eval 'hm "buffer-map BX 512; save-packet BX 64" | grep -q Compiled && hm "buffer-map BX 1024; save-packet BX 64" | grep -q "pinned with 1 x 512 bytes, declared with 1 x 1024; replacing"'
check CC-pin-buffer-shared   eval 'hm "shared-buffer-map BX 4 512; save-packet-keyed BX 1 64" | grep -q "declared with 4 x 512; replacing"'
check CC-r-buffer-refused    eval 'hm -r BX | grep -q "only maps of 64-bit values can be dumped"'
check CC-w-buffer-refused    eval 'hm -w BX 1 2 | grep -q "does not hold 64-bit values"'
check CC-r-missing           eval 'hm -r NOPE | grep -q "Could not open map"'
check CC-x-missing-key       eval 'hm "set map HX 1 5" >/dev/null; hm -x HX 99 | grep -q "could not delete"'
check CC-K-too-wide          eval 'hm -K "ip-src/24 src-mac eth-proto" -r HX | grep -q "a pack holds 64"'
"$BPFC" $M "pack K src-mac eth-proto; set map PK %K 1" >/dev/null 2>&1
"$BPFC" $M -w PK "pack src-mac=02:00:00:00:00:01 eth-proto=0x800" 7 >/dev/null 2>&1
check CC-K-mac-ethproto      eval 'hm -K "src-mac eth-proto" -r PK | grep -q "02:00:00:00:00:01.*0x0800\|02:00:00:00:00:01.*2048"'
"$BPFC" $M -w PK "pack ip-src/16=10.1.0.0 dst-mac=02:00:00:00:00:02" 9 >/dev/null 2>&1
check CC-K-prefix-mac        eval 'hm -K "ip-src/16 dst-mac" -r PK | grep -q "10.1.0.0/16.*02:00:00:00:00:02"'
check CC-V-mac               eval 'hm -w PK 3 "pack src-mac=02:00:00:00:00:03" >/dev/null; hm -V "src-mac" -r PK | grep -q "02:00:00:00:00:03"'

# -R: maps joined on their keys
"$BPFC" $M "get map HJ 1 V" >/dev/null 2>&1        # creates HJ
for w in "HM 1 5" "HM 2 6" "HM 0x10 7" "HJ 2 9" "HJ 0x10 0xab"; do "$BPFC" $M -w $w >/dev/null; done
R=$("$BPFC" $M -R HM,HJ,NOPE 2>/dev/null)
check CC-join-header         eval '[ "$(echo "$R" | head -1)" = "# key HM HJ NOPE" ]'
check CC-join-both           eval 'echo "$R" | grep -qx "0x0000000000000010 0x7 0xab -"'
check CC-join-one            eval 'echo "$R" | grep -qx "0x0000000000000002 0x6 0x9 -" && echo "$R" | grep -qx "0x0000000000000001 0x5 - -"'
check CC-join-keys-once      eval '[ $(echo "$R" | grep -c "^0x") -eq 3 ]'
check CC-join-missing-warns  eval '"$BPFC" $M -R HM,NOPE 2>&1 >/dev/null | grep -q "NOPE.*not pinned"'
check CC-join-none           eval '! "$BPFC" $M -R NOPE,NOPE2 >/dev/null 2>&1'
check CC-join-buffer-refused eval '"$BPFC" $M "buffer-map B 512; save-packet B 64" >/dev/null 2>&1; ! "$BPFC" $M -R HM,B >/dev/null 2>&1'
rm -f output.bpf

tests_exit
