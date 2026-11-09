#!/bin/bash
#
# XDP programs (bpfc -d xdp) and bpfcd's interfaces.d/<if>/xdp.bpfc.
#
#   bash tests/test-xdp.sh [-d]        -d: show the daemon log on failures
#
# Topology (generic XDP on the DUT's veth ends):
#
#   XB vb 10.9.0.2 ---- va 10.9.0.1  XA  vc 10.8.0.1 ---- vd 10.8.0.2 XC
#
# Senders have tx checksum offload off, so packets carry full checksums and
# the receiver verifies what the XDP program rewrote.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root xdp
require_cmds xdp ip ping nc tcpdump ethtool python3
TOP=$PWD
BPFC=$TOP/bpfc
BPFCD=$TOP/bpfcd/bpfcd
BPFCCTL=$TOP/bpfcd/bpfcctl
for b in "$BPFC" "$BPFCD" "$BPFCCTL"; do [ -x "$b" ] || { test_fail "xdp ($b not built: make)"; tests_exit; }; done
DEBUG=0
[ "$1" = "-d" ] && DEBUG=1

T=$(mktemp -d /tmp/bpfc-xdp.XXXXXX)
DPID=
cleanup() {
	[ -n "$DPID" ] && kill "$DPID" 2>/dev/null && wait "$DPID" 2>/dev/null
	for n in XA XB XC; do ip netns del xdp$n 2>/dev/null; done
	ip link del xdpdA 2>/dev/null
	ip link del xdpdC 2>/dev/null
	umount "$T/m" 2>/dev/null
	umount "$T/fm" 2>/dev/null
	rm -rf "$T"
	rm -f "$TESTS_FAILED_FILE"
}
trap cleanup EXIT
ulimit -l unlimited

A="ip netns exec xdpXA"
B="ip netns exec xdpXB"
C="ip netns exec xdpXC"
for n in XA XB XC; do ip netns del xdp$n 2>/dev/null; ip netns add xdp$n; ip -n xdp$n link set lo up; done
ip link add va netns xdpXA type veth peer name vb netns xdpXB
ip link add vc netns xdpXA type veth peer name vd netns xdpXC
ip -n xdpXA addr add 10.9.0.1/24 dev va; ip -n xdpXB addr add 10.9.0.2/24 dev vb
ip -n xdpXA addr add 10.8.0.1/24 dev vc; ip -n xdpXC addr add 10.8.0.2/24 dev vd
for x in "xdpXA va" "xdpXA vc" "xdpXB vb" "xdpXC vd"; do set -- $x; ip -n $1 link set $2 up; ip netns exec $1 ethtool -K $2 tx off >/dev/null 2>&1; done
VA_MAC=$(ip -n xdpXA -br link show va | awk '{print $3}')
VD_MAC=$(ip -n xdpXC -br link show vd | awk '{print $3}')
VC_MAC=$(ip -n xdpXA -br link show vc | awk '{print $3}')
ip -n xdpXB neigh replace 10.9.0.99 lladdr "$VA_MAC" dev vb
$B ping -c1 -W2 10.9.0.1 >/dev/null 2>&1   # resolve ARP both ways before any program

xdp_id() { ip -n "$1" -d link show "$2" | sed -n 's/.*prog\/xdp id \([0-9]*\).*/\1/p'; }
load()   { $A "$BPFC" -i va -d xdp "$@" >"$T/out" 2>&1 || { cat "$T/out" | head -5 | sed 's/^/    /'; return 1; }; }
pings()  { $B ping -c1 -W1 -s "${2:-56}" "$1" >/dev/null 2>&1; }
csum_errors() { $A nstat -az "$1" 2>/dev/null | awk -v k="$1" '$1 == k {print $2}'; }
# udp_to <dst ip> <dst port> <listen ip> <listen port>: one datagram arrives at the listener
udp_to() {
	rm -f "$T/udp"
	$A timeout 3 nc -u -l "$3" "$4" > "$T/udp" & local l=$!
	sleep 0.3
	echo "xdp-$RANDOM" | $B nc -u -w1 "$1" "$2"
	sleep 0.5; kill $l 2>/dev/null; wait $l 2>/dev/null
	[ -s "$T/udp" ]
}
# capture_start <ns> <dev> <count> <filter>: tcpdump -e -vv of up to count
# packets, for at most 5 s; returns once tcpdump is listening (it can take
# a while to start, e.g. when it drops privileges). No -Q: frames are told
# apart by their MAC addresses (-e) where the direction matters.
capture_start() {
	rm -f "$T/cap" "$T/cap.err"
	ip netns exec "$1" timeout 5 tcpdump -enn -vv -i "$2" -c "$3" "$4" > "$T/cap" 2>"$T/cap.err" & CAP=$!
	for _ in $(seq 50); do grep -q "listening on" "$T/cap.err" 2>/dev/null && break; sleep 0.1; done
	sleep 0.2
}
capture_wait()  { wait $CAP 2>/dev/null; }
# frame_from <src mac> <dst mac> <pattern>: a captured frame between those MACs whose next line matches
frame_from() { grep -i -A1 "$1 > $2" "$T/cap" | grep -q "$3"; }

echo "compile"
bad_msg() { local out; out=$("$BPFC" "${@:3}" 2>&1); local rc=$?
	if [ $rc -ne 0 ] && [ $rc -lt 128 ] && [[ "$out" == *"$2"* ]]; then test_pass "$1"; else test_fail "$1"; echo "$out" | head -2 | sed 's/^/    /'; fi; }
bad_msg XDP-err-skb-mark   "'set skb-mark' is not available in XDP programs" -d xdp "set skb-mark 5"
bad_msg XDP-err-reclassify "'reclassify' is not available in XDP programs"   -d xdp "reclassify"
bad_msg XDP-err-clone      "XDP cannot clone packets"                        -d xdp "clone lo"
bad_msg XDP-err-redir-in   "can only redirect out of an interface"          -d xdp "redirect lo ingress"
bad_msg XDP-err-prio       "-p does not apply to -d xdp"                     -d xdp -p 5 "drop"
bad_msg XDP-err-tx-on-tc   "tx is only available in XDP programs"            "tx"
bad_msg XDP-err-bad-dir    "'ingress', 'egress' or 'xdp'"                    -d sideways "drop"
mkdir -p "$T/fm"; mount -t bpf bpffs "$T/fm"
bad_msg XDP-err-ip-frag    "'ip-frag' is not available in XDP programs"      -m "$T/fm" -d xdp "ip-frag 500 3000"
bad_msg XDP-err-ip-defrag  "'ip-defrag' is not available in XDP programs"    -m "$T/fm" -d xdp "ip-defrag"
umount "$T/fm"
check XDP-const-xdp  eval '[ "$("$BPFC" -d xdp -E "when \$XDP == 1; drop; otherwise; accept; end-when")" = "drop;" ]'
check XDP-const-hook eval '[ "$("$BPFC" -d egress -E "debug-log \$HOOK \$XDP")" = "debug-log egress 0;" ]'
check XDP-compile-only eval '"$BPFC" -d xdp "match tcp; drop" | grep -q "Compiled"'

echo "every compile-suite command: loads as XDP or is refused at compile time"
XDP_SWEEP_IF=va $A bash tests/test-compile.sh > "$T/sweep" 2>&1
$A "$BPFC" -i va -d xdp -D   # the sweep leaves its last program attached
nl=$(grep -c "^XDP-LOADS" "$T/sweep"); nr=$(grep -c "^XDP-REFUSED" "$T/sweep")
if grep -q "FAIL" "$T/sweep"; then test_fail "XDP-sweep ($nl load, $nr refused)"; grep -A4 "FAIL" "$T/sweep" | head -30 | sed 's/^/    /'
else test_pass "XDP-sweep ($nl load, $nr refused, none rejected by the verifier)"; fi

echo "attach and actions"
check XDP-baseline-ping pings 10.9.0.1
load -I "match icmp; drop"
check XDP-attached-generic eval 'ip -n xdpXA link show va | grep -q xdpgeneric'
check XDP-info-line   grep -q "BPFC_INFO id=[0-9]* tag=.* dir=xdp" "$T/out"
check XDP-drop-icmp   eval '! pings 10.9.0.1'
check XDP-udp-passes  udp_to 10.9.0.1 5000 10.9.0.1 5000
id1=$(xdp_id xdpXA va)
load "accept"
id2=$(xdp_id xdpXA va)
check XDP-replace     eval '[ -n "$id2" ] && [ "$id2" != "$id1" ]'
check XDP-accept      pings 10.9.0.1
load "continue"
check XDP-continue-passes pings 10.9.0.1
load "get len L; match val L gt 1000; drop; end-match"
check XDP-len-small   pings 10.9.0.1 100
check XDP-len-large   eval '! pings 10.9.0.1 1200'
$A "$BPFC" -i va -d xdp -D
check XDP-detach      eval '[ -z "$(xdp_id xdpXA va)" ]'
load "drop"
$A "$BPFC" -i va -d xdp -c
check XDP-clean       eval '[ -z "$(xdp_id xdpXA va)" ]'
check XDP-clean-pings pings 10.9.0.1

# tx: the program swaps the MACs and sends the frame back to XB
load "match udp; match udp-dst 7777; get src-mac S; get dst-mac D; set dst-mac %S; set src-mac %D; tx; end-match; end-match"
VB_MAC=$(ip -n xdpXB -br link show vb | awk '{print $3}')
capture_start xdpXB vb 4 "udp dst port 7777"
echo hi | $B nc -u -w1 10.9.0.1 7777; echo hi | $B nc -u -w1 10.9.0.1 7777
capture_wait
check XDP-tx-reflects frame_from "$VA_MAC" "$VB_MAC" "10.9.0.2.[0-9]* > 10.9.0.1.7777"

# redirect: UDP to port 8888 leaves through vc towards XC
load "match udp; match udp-dst 8888; set dst-mac $VD_MAC; set src-mac $VC_MAC; redirect vc; end-match; end-match"
capture_start xdpXC vd 2 "udp dst port 8888"
echo hi | $B nc -u -w1 10.9.0.1 8888; echo hi | $B nc -u -w1 10.9.0.1 8888
capture_wait
check XDP-redirect    frame_from "$VC_MAC" "$VD_MAC" "> 10.9.0.1.8888"
check XDP-redirect-not-local eval '! udp_to 10.9.0.1 8888 10.9.0.1 8888'

echo "checksums (rewritten in place, verified by the receiver)"
u0=$(csum_errors UdpInCsumErrors); i0=$(csum_errors IpInHdrErrors)
load "match udp; match ip-dst 10.9.0.99; set ip-dst 10.9.0.1; end-match; end-match"
check XDP-csum-ip-dst-udp     udp_to 10.9.0.99 5000 10.9.0.1 5000
load "match udp; match udp-dst 6001; set udp-dst 5001; end-match; end-match"
check XDP-csum-udp-port       udp_to 10.9.0.1 6001 10.9.0.1 5001
load "match ip; set ip-tos 0x20; end-match"
check XDP-csum-ip-tos         udp_to 10.9.0.1 5000 10.9.0.1 5000
check XDP-csum-no-udp-errors  eval '[ "$(csum_errors UdpInCsumErrors)" = "$u0" ]'
check XDP-csum-no-ip-errors   eval '[ "$(csum_errors IpInHdrErrors)" = "$i0" ]'
load "match tcp; match ip-dst 10.9.0.99; set ip-dst 10.9.0.1; set tcp-dst 5002; end-match; end-match"
capture_start xdpXA va 1 "tcp dst port 5002"
$B timeout 1 bash -c 'echo > /dev/tcp/10.9.0.99/80' 2>/dev/null
capture_wait
check XDP-csum-tcp            grep -q "cksum 0x[0-9a-f]* (correct)" "$T/cap"
# a UDP datagram without a checksum (0) keeps 0 (BPF_F_MARK_MANGLED_0)
load "match udp; match udp-dst 6002; set ip-dst 10.9.0.1; end-match; end-match"
capture_start xdpXA va 1 "udp dst port 6002"
$B python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 11, 1)  # SO_NO_CHECK
s.sendto(b"nocsum", ("10.9.0.1", 6002))'
capture_wait
check XDP-csum-udp-zero-kept  grep -q "no cksum" "$T/cap"

echo "VLAN tags are in the packet"
mkdir -p "$T/m"; mount -t bpf bpffs "$T/m"
load -m "$T/m" "match vlan; calc-map add VL 1 1; drop; end-match"
$B python3 -c '
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp
sendp(Ether(dst="'"$VA_MAC"'")/Dot1Q(vlan=100)/IP(dst="10.100.0.1")/ICMP(), iface="vb", count=3, verbose=0)' 2>/dev/null
check XDP-match-vlan eval '"$BPFC" -m "$T/m" -r VL 2>/dev/null | grep -q "Key: 0x0*1 -> Value: 0x0*3$"'
$A "$BPFC" -i va -d xdp -D; umount "$T/m"

echo "resizing (bpf_xdp_adjust_head / adjust_tail), frames checked byte for byte"
RZ="python3 $TOP/tests/xdp-resize.py"
rz() { # rz <case> <program>: the program changes XB's frame and redirects it to XC
	# (a program with its own redirect is used as it is)
	local c=$1; shift
	local p="$*"
	[[ "$p" == *redirect* ]] || p="$p ; redirect vc"
	if ! load "$p"; then test_fail "XDP-resize-$c (load)"; return; fi
	rm -f "$T/rz.out" "$T/rz.ready"
	$C $RZ sniff vd "$T/rz.out" "$T/rz.ready" & local s=$!
	for _ in $(seq 80); do [ -e "$T/rz.ready" ] && break; sleep 0.1; done
	$B $RZ send vb "$c"
	wait $s
	check "XDP-resize-$c" env FIB_SMAC="$VC_MAC" FIB_DMAC="$VD_MAC" $RZ check "$c" "$T/rz.out"
}
mpls_words() { # the README / test-mpls.sh label arithmetic: next-hop label 20, PW label 16, TTL 225
	echo "decl MPLS1 4; decl MPLS2 4;
	set val MPLS1 20; calc lsh MPLS1 3; calc or MPLS1 0; calc lsh MPLS1 1; calc or MPLS1 0; calc lsh MPLS1 8; calc or MPLS1 225; calc bswap MPLS1;
	set val MPLS2 16; calc lsh MPLS2 3; calc or MPLS2 0; calc lsh MPLS2 1; calc or MPLS2 1; calc lsh MPLS2 8; calc or MPLS2 225; calc bswap MPLS2;" | tr -d '\n\t'
}
NS_MAC=02:00:00:00:00:aa; ND_MAC=02:00:00:00:00:bb
rz encap-mpls     "match ip; encap-mpls label 16 bos 1"
rz decap-mpls     "match mpls; decap-mpls"
rz decap-mpls-cw  "match mpls; decap-mpls"
# pw-encap as in test-mpls.sh's mpls_out_nh: fib-lookup (a bpf helper call from the XDP
# path) gives the next hop's MACs and interface, toward XC through vc. The kernel's FIB
# helper needs forwarding on and the neighbour resolved.
$A sysctl -qw net.ipv4.conf.all.forwarding=1 net.ipv4.conf.va.forwarding=1
ip -n xdpXA neigh replace 10.8.0.2 lladdr "$VD_MAC" dev vc
pw_encap() { # pw_encap <next hop> <header bytes>
	echo "decl FIB_DMAC 8; $(mpls_words) fib-lookup $1; match val %FIB_RESULT eq 0; add-head-bytes $2;
	set bytes 14 4 %MPLS1; set bytes 18 4 %MPLS2; set eth-proto 0x8847; set dst-mac %FIB_DMAC; set src-mac %FIB_SMAC;
	redirect %FIB_IFINDEX egress" | tr -d '\n\t'
}
rz pw-encap       "$(pw_encap 10.8.0.2 22)"
rz pw-encap-cw    "$(pw_encap 10.8.0.2 26)"
rz pw-encap-miss  "$(pw_encap 10.7.7.7 22); end-match; redirect vc"
# fib-lookup %VAR with the packet's own destination (host order, as get ip-dst gives it;
# 10.8.0.2 differs from its byte swap), and FIB_IP_DST coming back in the same order
rz fib-var        "decl D 4; get ip-dst D; fib-lookup %D; match val %FIB_RESULT eq 0; set dst-mac %FIB_DMAC; set src-mac %FIB_SMAC; redirect %FIB_IFINDEX; end-match; drop"
rz fib-ip-dst     "decl D 4; get ip-dst D; fib-lookup %D; match val %FIB_RESULT eq 0; match val %FIB_IP_DST eq %D; set dst-mac %FIB_DMAC; set src-mac %FIB_SMAC; redirect %FIB_IFINDEX; end-match; end-match; drop"
$A sysctl -qw net.ipv4.conf.all.forwarding=0 net.ipv4.conf.va.forwarding=0
rz pw-decap       "match mpls; match mpls-label 16; del-bytes 0 18"
rz pw-decap-cw    "match mpls; match mpls-label 16; del-bytes 0 22"
rz add-l2-bytes   "add-l2-bytes 20"
rz del-l2-bytes   "del-l2-bytes 4"
rz add-bytes-near "add-bytes 20 6"
rz del-bytes-near "del-bytes 20 6"
rz add-bytes-far  "add-bytes 100 4"
rz del-bytes-far  "del-bytes 100 4"
rz push-vlan      "push-vlan 100 3"
rz pop-vlan       "pop-vlan"
rz push-qinq      "push-qinq 10 20"
rz push-eth       "push-eth $ND_MAC $NS_MAC"
rz pop-eth        "pop-eth"
rz set-len        "set len 80"
rz decap-gre      "decap-gre"
rz set-vlan-id            "set vlan-id 200"
rz set-vlan-id-var        "decl V 2; set val V 201; set vlan-id %V"
rz set-vlan-id-qinq       "set vlan-id 200"
rz set-vlan-id-untagged   "set vlan-id 200"
rz match-vlan-id          "match vlan-id 100; set vlan-id 300; end-match"
rz match-vlan-id-miss     "match vlan-id 100; set vlan-id 300; end-match"
rz match-vlan-id-var      "decl V 2; set val V 100; match vlan-id %V; set vlan-id 300; end-match"
rz match-vlan-id-range    "match vlan-id 10-20; set vlan-id 300; end-match"
rz match-vlan-id-untagged "match vlan-id 0; set vlan-id 300; end-match"
$A "$BPFC" -i va -d xdp -D

echo "XDP and TC together"
load "match udp; match udp-dst 6003; drop; end-match; end-match"
$A "$BPFC" -i va -d ingress -p 10 "match udp; match udp-dst 6004; drop; end-match; end-match" >/dev/null
check XDP-and-tc-xdp-drops  eval '! udp_to 10.9.0.1 6003 10.9.0.1 6003'
check XDP-and-tc-tc-drops   eval '! udp_to 10.9.0.1 6004 10.9.0.1 6004'
check XDP-and-tc-others     udp_to 10.9.0.1 6005 10.9.0.1 6005
$A "$BPFC" -i va -d xdp -D; $A "$BPFC" -i va -c

# ---------------- bpfcd ----------------
echo "bpfcd: interfaces.d/<if>/xdp.bpfc"
CFG=$T/etc/interfaces.d
mkdir -p "$CFG/xdpdA" "$CFG/%veth%" "$CFG/%all%" "$T/run"
printf 'match icmp; drop\n'  > "$CFG/xdpdA/xdp.bpfc"
printf 'accept\n'            > "$CFG/%veth%/xdp.bpfc"
printf 'continue\n'          > "$CFG/%all%/xdp.bpfc"
mkdir -p "$CFG/lo"; printf '# no XDP on lo\n' > "$CFG/lo/xdp.bpfc"
write_conf() {
	cat > "$T/etc/bpfc.conf" <<-EOF
	bpfc_path = $BPFC
	config_dir = $CFG
	state_dir = $T/run
	on_external_change = ${1:-reinstall}
	remove_on_stop = ${2:-no}
	EOF
}
eventually() { for _ in $(seq 50); do "$@" && return 0; sleep 0.1; done; return 1; }
hid()        { ip -d link show "$1" 2>/dev/null | sed -n 's/.*prog\/xdp id \([0-9]*\).*/\1/p'; }
has_xdp()    { [ -n "$(hid "$1")" ]; }
no_xdp()     { [ -z "$(hid "$1")" ]; }
status_of()  { awk -v i="$1" '$1=="slot" { delete kv; for (n = 2; n <= NF; n++) { split($n, x, "="); kv[x[1]] = x[2] }
               if (kv["iface"] == i && kv["dir"] == "xdp") print kv["status"] }' "$T/run/state"; }
is_status()  { [ "$(status_of "$1")" = "$2" ]; }
kind_of()    { ip -d link show "$1" | grep -o 'xdpgeneric\|xdpdrv' | head -1; }
start_daemon() { "$BPFCD" -c "$T/etc/bpfc.conf" >> "$T/log" 2>&1 & DPID=$!; eventually test -s "$T/run/state"; }
stop_daemon()  { kill "$DPID"; wait "$DPID" 2>/dev/null; DPID=; }
reload()       { "$BPFCCTL" -c "$T/etc/bpfc.conf" reload >/dev/null; }
dcheck() { local n=$1; shift; if "$@"; then test_pass "$n"; else test_fail "$n"; [ $DEBUG -eq 1 ] && tail -15 "$T/log" | sed 's/^/    /'; fi; }

ip link del xdpdA 2>/dev/null; ip link del xdpdC 2>/dev/null
ip link add xdpdA type veth peer name xdpdB
ip link set xdpdA up; ip link set xdpdB up
write_conf
start_daemon
dcheck BD-XDP-installed           eventually has_xdp xdpdA
dcheck BD-XDP-generic-mode        eval '[ "$(kind_of xdpdA)" = xdpgeneric ]'
dcheck BD-XDP-status-installed    is_status xdpdA installed
dcheck BD-XDP-kind-template       eventually has_xdp xdpdB
dcheck BD-XDP-template-path       eval 'grep "iface=xdpdB dir=xdp" "$T/run/state" | grep -q "%25veth%25/xdp.bpfc"'
dcheck BD-XDP-own-file-wins       eval 'grep "iface=xdpdA dir=xdp" "$T/run/state" | grep -q "xdpdA/xdp.bpfc"'
dcheck BD-XDP-empty-excludes      eval 'is_status lo excluded && no_xdp lo'
dcheck BD-XDP-prog-name           eval 'ip -d link show xdpdA | grep -q "name xdpdA_xdp_0"'
dcheck BD-XDP-ctl-status          eval '"$BPFCCTL" -s "$T/run" status | grep -q "^xdpdA *xdp *- *installed"'
dcheck BD-XDP-ctl-show            eval '"$BPFCCTL" -s "$T/run" show xdpdA xdp | grep -q "^xdpdA xdp"'
dcheck BD-XDP-ctl-show-slash      eval '"$BPFCCTL" -s "$T/run" show xdpdA/xdp | grep -q "match icmp"'
dcheck BD-XDP-ctl-excluded-clean  eval '! "$BPFCCTL" -s "$T/run" status | grep "^lo " | grep -q "reload pending"'

id1=$(hid xdpdA)
printf 'match udp; drop\n' > "$CFG/xdpdA/xdp.bpfc"; reload
dcheck BD-XDP-edit-replaces       eval 'id=$(hid xdpdA); [ -n "$id" ] && [ "$id" != "$id1" ]'

printf 'set skb-mark 1\n' > "$CFG/xdpdA/xdp.bpfc"; reload
dcheck BD-XDP-failed              is_status xdpdA failed
dcheck BD-XDP-failed-removed      no_xdp xdpdA
dcheck BD-XDP-failed-error-log    eval 'grep -q "not available in XDP programs" "$T/run/errors/xdpdA.xdp.0.log"'
dcheck BD-XDP-ctl-show-failed     eval '"$BPFCCTL" -s "$T/run" show xdpdA xdp | grep -q "not available in XDP"'

printf 'match icmp; drop\n' > "$CFG/xdpdA/xdp.bpfc"; reload
dcheck BD-XDP-fixed               eval 'is_status xdpdA installed && has_xdp xdpdA'
id1=$(hid xdpdA)
ip link set xdpdA xdpgeneric off
dcheck BD-XDP-external-removal    eventually eval 'id=$(hid xdpdA); [ -n "$id" ] && [ "$id" != "$id1" ]'
id1=$(hid xdpdA)
"$BPFC" -i xdpdA -d xdp "accept" >/dev/null
dcheck BD-XDP-external-replace    eventually eval 'grep -q "replaced by an xdpgeneric program" "$T/log" && [ "$(hid xdpdA)" != "" ] && is_status xdpdA installed'

# restart: programs stay attached and are adopted, not reloaded
id1=$(hid xdpdA)
stop_daemon
dcheck BD-XDP-stays-on-stop       eval '[ "$(hid xdpdA)" = "$id1" ]'
start_daemon
dcheck BD-XDP-adopted             eval 'eventually grep -q "adopted" "$T/log" && [ "$(hid xdpdA)" = "$id1" ]'

# deleting the interface's file: the %veth% template takes over
rm "$CFG/xdpdA/xdp.bpfc"; reload
dcheck BD-XDP-delete-falls-back   eval 'grep "iface=xdpdA dir=xdp" "$T/run/state" | grep -q "%25veth%25" && has_xdp xdpdA'
rm "$CFG/%veth%/xdp.bpfc"; reload
dcheck BD-XDP-all-template        eval 'grep "iface=xdpdA dir=xdp" "$T/run/state" | grep -q "%25all%25" && has_xdp xdpdA'
rm "$CFG/%all%/xdp.bpfc"; reload
dcheck BD-XDP-delete-removes      eventually no_xdp xdpdA

# a new interface gets the template's program
printf 'accept\n' > "$CFG/%veth%/xdp.bpfc"; reload
ip link add xdpdC type veth peer name xdpdD
dcheck BD-XDP-new-iface           eventually has_xdp xdpdC

# on_external_change = log
stop_daemon
write_conf log
start_daemon
ip link set xdpdC up
ip link set xdpdC xdpgeneric off
dcheck BD-XDP-log-policy          eventually is_status xdpdC removed-externally
dcheck BD-XDP-log-leaves-it       no_xdp xdpdC
reload
dcheck BD-XDP-reload-restores     eventually has_xdp xdpdC

# unmanaged programs are listed by status -a
"$BPFC" -i xdpdB -d xdp -D 2>/dev/null; sleep 0.3
stop_daemon
"$BPFC" -i xdpdB -d xdp "drop" >/dev/null
dcheck BD-XDP-ctl-all-unmanaged   eval '"$BPFCCTL" -s "$T/run" status -a | grep -q "^xdpdB *xdp *- *xdpgeneric"'
"$BPFC" -i xdpdB -d xdp -D

# remove_on_stop
write_conf reinstall yes
start_daemon
dcheck BD-XDP-before-stop         eventually has_xdp xdpdC
stop_daemon
dcheck BD-XDP-remove-on-stop      no_xdp xdpdC

tests_exit
