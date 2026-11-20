#!/bin/bash
#
# IPv4 de-duplication (programs/dedup): dedup-iface.bpfc and dedup-global.bpfc
# on lo, in a new network and mount namespace, and bpfc-dedup reading the maps.
#
#   bash tests/test-dedup.sh
#
# tests/dedup-send.py sends crafted frames with AF_PACKET (so IP IDs, DF/MF and
# checksums are exactly as given) and counts what a UDP socket receives. On lo
# every frame passes TC egress and then TC ingress. Each case uses its own
# source address, so the cases do not share flows; programs are replaced in
# place (same priority) to change settings.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root dedup
require_cmds dedup python3 unshare mount
TOP=$PWD
BPFC=$TOP/bpfc
[ -x "$BPFC" ] || { test_fail "dedup (bpfc not built: make)"; tests_exit; }

if [ -z "${DEDUP_TEST_NS:-}" ]; then
	rm -f "$TESTS_FAILED_FILE"
	DEDUP_TEST_NS=1 exec unshare --net --mount bash "$0" "$@"
fi

T=$(mktemp -d /tmp/bpfc-dedup.XXXXXX)
trap 'umount "$T/bpf" 2>/dev/null; rm -rf "$T"; rm -f "$TESTS_FAILED_FILE"' EXIT
INC=$TOP/programs/dedup/include
EX=$TOP/programs/dedup/examples
SEND="python3 $TOP/tests/dedup-send.py"
STATUS() { BPFC_BIN=$BPFC "$TOP/programs/dedup/bpfc-dedup" -m "$T/bpf" "$@"; }

$SEND --lo-up || { test_fail "dedup (cannot set up lo)"; tests_exit; }
mkdir -p "$T/bpf" && mount -t bpf bpf "$T/bpf" || { test_fail "dedup (cannot mount bpffs)"; tests_exit; }

# The program under test: UDP to 5000, all TCP and all ICMP go through dedup,
# from the test's sources only (127.1/16): the kernel's answers (TCP RST, ICMP
# timestamp replies) come from 127.0.0.1 and stay out of the counters.
cat > "$T/iface.bpfc" <<'EOF'
include dedup-iface.bpfc;
match ip-src 127.1.0.0/16;
  match udp; match udp-dst 5000; dedup; end-match; end-match;
  match tcp; dedup; end-match;
  match icmp; dedup; end-match;
end-match;
EOF
sed 's/dedup-iface/dedup-global/' "$T/iface.bpfc" > "$T/global.bpfc"

# load <file> <dir> [bpfc options]: attach at priority 10 (replacing)
load() { local f=$1 d=$2; shift 2; "$BPFC" -L "$INC" -m "$T/bpf" -i lo -d "$d" -p 10 "$@" -f "$f" > "$T/load.log" 2>&1; }
unload() { "$BPFC" -i lo -d "$1" -p 10 -D >/dev/null 2>&1; }
# ctr <scope> <index>: counter value
ctr() {
	local line k
	k=$(printf '0x%016x' "$2")
	while IFS= read -r line; do
		[[ $line =~ Key:\ $k\ -\>\ Value:\ 0x([0-9a-f]+) ]] && echo $((16#${BASH_REMATCH[1]}))
	done < <("$BPFC" -m "$T/bpf" -r "DDC_$1")
}
is() { local v; v=$(ctr "$1" "$2"); [ "$v" = "$3" ] || { echo "  DDC_$1[$2] = $v, expected $3"; return 1; }; }
recv() { local n; n=$($SEND --recv 5000 "${@:2}"); [ "$n" = "$1" ] || { echo "  received $n, expected $1"; return 1; }; }
reset() { STATUS -z "$@" >/dev/null; }

# ---- compile-time checks
check "dedup-iface loads at ingress"  load "$T/iface.bpfc" ingress
check "dedup-iface maps are per interface and hook" eval 'for m in DDS DDQ DDF DDL DDC DDH; do test -e "$T/bpf/${m}_I_lo" || exit 1; done'
check "dedup-iface verifies within budget" eval '"$BPFC" -L "$INC" -m "$T/bpf" -T -i lo -f "$T/iface.bpfc" > "$T/t.log" 2>&1'
check "dedup-global refuses egress" eval '! "$BPFC" -L "$INC" -m "$T/bpf" -T -i lo -d egress -f "$T/global.bpfc" > "$T/t.log" 2>&1 && grep -q "ingress-only" "$T/t.log"'
check "dedup-iface loads as XDP (generic)" eval '"$BPFC" -L "$INC" -m "$T/bpf" -T -i lo -d xdp -f "$T/iface.bpfc" > "$T/t.log" 2>&1'
check "dedup count mode verifies" eval '"$BPFC" -L "$INC" -m "$T/bpf" -T -i lo -s DD_MODE=count -s DD_IDS=0 -s DD_PKTS=0 -f "$T/iface.bpfc" > "$T/t.log" 2>&1'
for f in $(find "$EX" -name '*.bpfc' | sort); do
	check "example ${f#$EX/} verifies" eval '"$BPFC" -L "$INC" -m "$T/bpf" -T -i lo -f "$f" > "$T/t.log" 2>&1'
done

# ---- per-interface, ingress
reset I_lo
check "duplicate UDP pair: one delivered"       recv 1 src=127.1.0.10,id=100 src=127.1.0.10,id=100
check "same ID, different payload: both"        recv 2 src=127.1.0.11,id=200,data=a src=127.1.0.11,id=200,data=b
check "traffic not handed to dedup passes"      eval '[ "$($SEND --recv 5001 src=127.1.0.12,id=300,dport=5001 src=127.1.0.12,id=300,dport=5001)" = 2 ]'
check "same ID, other destination: both"        recv 2 src=127.1.0.13,id=310 src=127.1.0.13,dst=127.0.0.3,id=310
$SEND src=127.1.0.14,id=400,mf=1 src=127.1.0.14,id=400,mf=1 src=127.1.0.14,id=401,off=10 src=127.1.0.14,id=401,off=10
$SEND proto=tcp,src=127.1.0.15,id=500,data=a proto=tcp,src=127.1.0.15,id=500,data=b proto=tcp,src=127.1.0.15,id=501 proto=tcp,src=127.1.0.15,id=501
$SEND proto=icmp,src=127.1.0.16,df=1,id=0 proto=icmp,src=127.1.0.16,df=1,id=0 proto=icmp,src=127.1.0.16,id=0 proto=icmp,src=127.1.0.16,id=0 proto=icmp,src=127.1.0.16,df=1,id=9 proto=icmp,src=127.1.0.16,df=1,id=9
check "counters: duplicates"   is I_lo 1 4     # udp 100, tcp 501, icmp id 0 without DF, icmp id 9
check "counters: fragments"    is I_lo 6 4
check "counters: atomic ID 0"  is I_lo 7 2
check "counters: replaced"     is I_lo 8 2     # udp 200, tcp 500
check "counters: checked"      is I_lo 0 14
check "counters: new"          is I_lo 2 10
check "history holds the duplicates" eval 'STATUS I_lo | grep -q "127.1.0.10 *-> 127.0.0.1 *udp *100 *lo"'
check "history newest first"   eval 'STATUS -H 1 I_lo | grep -q "icmp *9 *lo" && [ "$(STATUS -H 1 I_lo | grep -c " -> ")" = 1 ]'
check "json output"            eval 'STATUS -j | python3 -c "import json,sys; d=json.load(sys.stdin); s=d[0]; assert s[\"scope\"]==\"I_lo\" and s[\"duplicates\"]==4 and len(s[\"history\"])==4 and s[\"settings\"][\"mode\"]==\"drop\", s"'
check "reset zeroes counters and history" eval 'reset I_lo && is I_lo 1 0 && is I_lo 9 0 && ! STATUS I_lo | grep -q " -> "'

# ---- expiry: time
load "$T/iface.bpfc" ingress -s DD_MS=50 && reset I_lo
check "time: copy after the window passes"      recv 2 src=127.1.0.20,id=600,wait=200 src=127.1.0.20,id=600
check "time: copy inside the window dropped"    recv 1 src=127.1.0.21,id=600,wait=10 src=127.1.0.21,id=600
check "time: counted"                           is I_lo 3 1

# ---- expiry: ID rollover (the ID advanced half the space since)
load "$T/iface.bpfc" ingress -s DD_MS=5000 && reset I_lo
check "rollover: ID advanced 65536, copy passes" recv 5 src=127.1.0.30,id=1 src=127.1.0.30,id=20001 src=127.1.0.30,id=40001 src=127.1.0.30,id=60001 src=127.1.0.30,id=1
check "rollover: ID advanced 20000, copy dropped" recv 2 src=127.1.0.31,id=1 src=127.1.0.31,id=20001 src=127.1.0.31,id=1
check "rollover: late copies are not an ID advance" recv 2 src=127.1.0.32,id=100 src=127.1.0.32,id=20100 src=127.1.0.32,id=100 src=127.1.0.32,id=20100
check "rollover: counted"                       is I_lo 4 1

# ---- expiry: packets of the flow
load "$T/iface.bpfc" ingress -s DD_MS=5000 -s DD_IDS=0 -s DD_PKTS=4 && reset I_lo
check "packets: 4 packets since, copy passes"   recv 5 src=127.1.0.40,id=10 src=127.1.0.40,id=11 src=127.1.0.40,id=12 src=127.1.0.40,id=13 src=127.1.0.40,id=10
check "packets: 3 packets since, copy dropped"  recv 3 src=127.1.0.41,id=10 src=127.1.0.41,id=11 src=127.1.0.41,id=12 src=127.1.0.41,id=10
check "packets: counted"                        is I_lo 5 1

# ---- count mode
load "$T/iface.bpfc" ingress -s DD_MODE=count && reset I_lo
check "count mode: duplicate delivered"         recv 2 src=127.1.0.50,id=700 src=127.1.0.50,id=700
check "count mode: counted"                     is I_lo 1 1
check "count mode: status says count"           eval 'STATUS I_lo | grep -q "mode count"'

# ---- egress and ingress of one interface: separate tables
load "$T/iface.bpfc" ingress && load "$T/iface.bpfc" egress && reset I_lo && reset E_lo
check "egress: duplicate dropped at egress"     recv 1 src=127.1.0.60,id=800 src=127.1.0.60,id=800
check "egress: counted at egress"               is E_lo 1 1
check "egress: a packet is not its own duplicate at ingress" eval 'is I_lo 1 0 && is I_lo 2 1'
unload egress

# ---- global
load "$T/global.bpfc" ingress && reset G 2>/dev/null
check "global: maps DDS_G and friends"          test -e "$T/bpf/DDS_G"
check "global: duplicate dropped"               recv 1 src=127.1.0.70,id=900 src=127.1.0.70,id=900
check "global: counted"                         is G 1 1
check "global: status names it"                 eval 'STATUS G | grep -q "global (G)"'
load "$T/global.bpfc" ingress -s DD_GROUP=pair1
check "global: DD_GROUP gives its own maps"     test -e "$T/bpf/DDS_pair1"
check "global: group dedups"                    recv 1 src=127.1.0.71,id=900 src=127.1.0.71,id=900
check "status lists every scope"                eval '[ "$(STATUS | grep -c "^== ")" = 4 ]'

tests_exit
