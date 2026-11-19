#!/bin/bash
#
# linkcap (programs/linkcap): per-neighbor loss and capacity from packet
# accounting, end to end in network namespaces.
#
#   bash tests/test-linkcap.sh
#
# Ethernet: A -- veth -- B, and A -- veth -- E (tests/link-emulator.py: rate,
# loss) -- veth -- B. Point-to-point raw IP: tun devices in A and B joined by
# tests/linkcap-tun-relay.py (the same kind of device as GRE, PPP or
# WireGuard). Multipoint GRE is only compiled: the test kernel has no ip_gre.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root linkcap
require_cmds linkcap ip python3 mount
TOP=$PWD
export BPFC=$TOP/bpfc
[ -x "$BPFC" ] || { test_fail "linkcap (bpfc not built: make)"; tests_exit; }
GEN=$TOP/programs/linkcap/bpfc-linkcap-gen
STATUS=$TOP/programs/linkcap/bpfc-linkcap-status
T=$(mktemp -d /tmp/bpfc-linkcap.XXXXXX)
NSA=lcA$$; NSB=lcB$$; NSE=lcE$$
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	for n in $NSA $NSB $NSE; do ip netns del $n 2>/dev/null; done
	umount "$T/bpf" 2>/dev/null; rm -rf "$T"; rm -f "$TESTS_FAILED_FILE"
}
trap cleanup EXIT
mkdir -p "$T/bpf" && mount -t bpf bpf "$T/bpf" || { test_fail "linkcap (cannot mount bpffs)"; tests_exit; }

# ------------------------------------------------------------ generator
check "linkcap gen: needs --link for a missing interface" eval '! "$GEN" -i nosuch0 -o - >/dev/null 2>&1'
check "linkcap gen: bad interval refused" eval '! "$GEN" -i x0 --link eth --interval 5ms -o - >/dev/null 2>&1'
check "linkcap gen: bad link refused" eval '! "$GEN" -i x0 --link vlan -o - >/dev/null 2>&1'
check "linkcap gen: mgre needs a valid --gre-hlen" eval '! "$GEN" -i x0 --link mgre --gre-hlen 6 -o - >/dev/null 2>&1'
check "linkcap gen: profiles listed" eval '"$GEN" --list-profiles | grep -q "^leo "'
check "linkcap gen: leo profile settings" eval '"$GEN" --show-profile leo | grep -q "^interval *200ms"'
check "linkcap gen: map suffix" eval '[ "$("$GEN" -i eth0 --map-prefix)" = "eth0 $("$GEN" -i eth0 --map-prefix | cut -d" " -f2)" ] && "$GEN" -i eth0 --map-prefix | grep -Eq " lc[a-z2-7]{8}$"'
for l in eth p2p mgre; do
	for h in 4 8 16; do
		[ $l = mgre ] || [ $h = 4 ] || continue
		"$GEN" -i c$l --link $l --gre-hlen $h -o "$T/gen" >/dev/null 2>&1
		for d in ingress egress; do
			f=$(ls "$T/gen/c$l/$d/"*.bpfc 2>/dev/null)
			if [ $l = eth ]; then S="-s IFMAC=02:00:00:00:00:01 -s L3OFF=14"; else S="-s IFMAC=00:00:00:00:00:00 -s L3OFF=0 -s IFTYPE=778"; fi
			check "linkcap $l (gre-hlen $h) $d compiles" eval '"$BPFC" -m "$T/bpf" -s IFNAME=lo -s HOOK=$d $S -f "$f" >"$T/cc.log" 2>&1'
		done
		rm -rf "$T/gen"
	done
done
rm -f "$T/bpf/"[A-Z]*

# ------------------------------------------------------------ helpers
# attach NS IF: generate into $T/cfg-NS and load both programs (extra args to the generator)
attach() {
	local ns=$1 i=$2; shift 2
	mkdir -p "$T/bpf/$ns"
	ip netns exec $ns "$GEN" -i $i -o "$T/cfg-$ns" "$@" >/dev/null || return 1
	local d f
	for d in ingress egress; do
		f=$(ls "$T/cfg-$ns/$i/$d/"*.bpfc)
		ip netns exec $ns "$BPFC" -i $i -d $d -p "$(basename "$f" .bpfc)" -m "$T/bpf/$ns" -f "$f" >"$T/load.log" 2>&1 || { cat "$T/load.log"; return 1; }
	done
}
st() { local ns=$1; shift; "$STATUS" -c "$T/cfg-$ns" -m "$T/bpf/$ns" "$@"; }
# kv NS KEY [neighbor]: KEY from the -1 line (of the neighbor, else the first)
kv() { st $1 -1 | { if [ -n "$3" ]; then grep "neighbor=$3 "; else head -1; fi; } | tr ' ' '\n' | sed -n "s/^$2=//p"; }
ctr() { st $1 -1 counters | tr ' ' '\n' | sed -n "s/^$2=//p"; }
between() { awk -v v="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(v != "" && v != "-" && v + 0 >= lo && v + 0 <= hi) }'; }
reset_ns() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=()
	for n in $NSA $NSB $NSE; do ip netns del $n 2>/dev/null; done
	rm -rf "$T/bpf/"lc* "$T"/cfg-*
	ip netns add $NSA; ip netns add $NSB
	ip -n $NSA link set lo up; ip -n $NSB link set lo up
}
offloads() { ip netns exec $1 ethtool -K $2 tso off gso off gro off "${@:3}" >/dev/null 2>&1 || true; }
# udp_blast NS DST MBIT SECONDS: UDP at MBIT Mbit/s (1200-byte datagrams)
udp_blast() {
	ip netns exec $1 python3 - "$2" "$3" "$4" <<'EOF'
import socket, sys, time
dst, mbit, secs = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
gap = 1228 * 8 / (mbit * 1e6); t = time.monotonic(); end = t + secs; buf = b"x" * 1200
while t < end:
    try: s.sendto(buf, (dst, 9))
    except OSError: pass
    t += gap
    d = t - time.monotonic()
    if d > 0: time.sleep(d)
EOF
}

# ------------------------------------------------------------ Ethernet, direct
reset_ns
ip link add va netns $NSA type veth peer name vb netns $NSB
ip -n $NSA addr add 10.0.0.1/24 dev va; ip -n $NSB addr add 10.0.0.2/24 dev vb
ip -n $NSA link set va up; ip -n $NSB link set vb up
offloads $NSA va; offloads $NSB vb
check "linkcap eth: programs load (A)" attach $NSA va
check "linkcap eth: programs load (B)" attach $NSB vb
ip netns exec $NSA ping -c 40 -i 0.05 -q 10.0.0.2 >/dev/null 2>&1
sleep 0.4
MACB=$(ip -n $NSB link show vb | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
check "linkcap eth: neighbor is B's MAC" eval '[ "$(kv $NSA neighbor)" = "$MACB" ]'
check "linkcap eth: reports answered" eval 'r=$(ctr $NSA reports_sent); [ "$r" -ge 5 ] && [ "$(ctr $NSA replies_received)" -eq "$r" ] && [ "$(ctr $NSB replies_sent)" -eq "$r" ]'
check "linkcap eth: samples taken" eval '[ "$(kv $NSA samples)" -ge 4 ]'
check "linkcap eth: counts agree (A sent, B received)" eval '[ "$(kv $NSA tx_packets)" -eq "$(kv $NSB rx_packets)" ] && [ "$(kv $NSA tx_bytes)" -eq "$(kv $NSB rx_bytes)" ]'
check "linkcap eth: 84 IP bytes per ping" eval '[ $(( $(kv $NSA tx_bytes) % 84 )) -eq 0 ] && [ "$(kv $NSA tx_packets)" -ge 40 ]'
check "linkcap eth: no loss, state under" eval '[ "$(kv $NSA loss_pct)" = 0.000 ] && [ "$(kv $NSA state)" = under ]'
check "linkcap eth: JSON parses" eval 'st $NSA -j | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"neighbors\"][0][\"state\"] == \"under\""'
check "linkcap eth: counters JSON parses" eval 'st $NSA -j counters | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"interfaces\"][0][\"reports_sent\"] > 0"'
if command -v tcpdump >/dev/null; then
	ip netns exec $NSB timeout 3 tcpdump -i vb -c 1 -xx 'ether proto 0x88b6 and ether[128:4] = 0x4c430101' >"$T/td" 2>/dev/null &
	sleep 0.5; ip netns exec $NSA ping -c 10 -i 0.1 -q 10.0.0.2 >/dev/null; wait
	# bytes 14..127 are zero: nothing of the cloned packet leaves with the report
	check "linkcap eth: report frame is 192 bytes, zero before the payload" eval 'grep -q "length 192" "$T/td" && [ "$(sed -n "s/^[[:space:]]*0x00[1-7]0: *//p" "$T/td" | tr -d " 0\n")" = "" ]'
else
	test_skip "linkcap eth: report frame layout (no tcpdump)"
fi
# TCP through both programs, with checksum offload on (clones of packets whose
# checksum is still pending): the data arrives intact
ip netns exec $NSA ethtool -K va tx on >/dev/null 2>&1
ip netns exec $NSB python3 -c '
import socket, hashlib
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("10.0.0.2", 5001)); s.listen(1)
c, _ = s.accept(); h = hashlib.sha256(); n = 0
while True:
    b = c.recv(65536)
    if not b: break
    h.update(b); n += len(b)
open("'"$T"'/tcp.rx", "w").write("%d %s\n" % (n, h.hexdigest()))' &
sleep 0.5
ip netns exec $NSA python3 -c '
import socket, hashlib, os, time
d = os.urandom(4 << 20); s = socket.create_connection(("10.0.0.2", 5001))
for i in range(0, len(d), 8192): s.sendall(d[i:i+8192]); time.sleep(0.0005)
s.close(); open("'"$T"'/tcp.tx", "w").write("%d %s\n" % (len(d), hashlib.sha256(d).hexdigest()))'
wait
check "linkcap eth: 4 MB of TCP intact" eval '[ -s "$T/tcp.tx" ] && cmp -s "$T/tcp.tx" "$T/tcp.rx"'
check "linkcap eth: reports went out during the transfer" eval '[ "$(ctr $NSA reports_sent)" -ge 10 ]'
# runtime settings
check "linkcap status set interval" eval 'st $NSA set va interval 100ms >/dev/null && st $NSA settings | grep -q "interval *100.000 ms (set)"'
check "linkcap status unset interval" eval 'st $NSA unset va interval >/dev/null && st $NSA settings | grep -q "interval *250.000 ms$"'
check "linkcap status refuses a bad setting" eval '! st $NSA set va interval 1ms 2>/dev/null && ! st $NSA set va nosuch 1 2>/dev/null'
# counter reset: B starts again with empty maps
R0=$(ctr $NSA counter_resets)
for d in ingress egress; do ip netns exec $NSB tc filter del dev vb $d 2>/dev/null; done
rm -f "$T/bpf/$NSB/"*
attach $NSB vb
ip netns exec $NSA ping -c 30 -i 0.05 -q 10.0.0.2 >/dev/null 2>&1
check "linkcap eth: the peer's counters starting again are noticed" eval '[ "$(ctr $NSA counter_resets)" -gt "$R0" ] && [ "$(kv $NSA last_reply_ms)" -lt 1000 ]'

# ------------------------------------------------------------ no reply, table full
for d in ingress egress; do ip netns exec $NSA tc filter del dev va $d 2>/dev/null; done
rm -rf "$T/bpf/$NSA" "$T/cfg-$NSA"
check "linkcap eth: programs load with --neighbors 2" attach $NSA va --neighbors 2
ip -n $NSA neigh add 10.0.0.8 lladdr 02:00:00:00:00:08 dev va
ip -n $NSA neigh add 10.0.0.9 lladdr 02:00:00:00:00:09 dev va
ip netns exec $NSA ping -c 10 -i 0.05 -q 10.0.0.2 >/dev/null 2>&1
ip netns exec $NSA ping -c 30 -i 0.05 -q -W 0.01 10.0.0.8 >/dev/null 2>&1
ip netns exec $NSA ping -c 3 -i 0.05 -q -W 0.01 10.0.0.9 >/dev/null 2>&1
sleep 1.2
check "linkcap eth: a neighbor without linkcap is no-reply" eval '[ "$(kv $NSA state 02:00:00:00:00:08)" = no-reply ]'
check "linkcap eth: the third neighbor is refused" eval '[ "$(ctr $NSA neighbors_refused)" -ge 1 ] && [ "$(st $NSA -1 | wc -l)" -eq 2 ]'

# ------------------------------------------------------------ Ethernet through the emulator
reset_ns
ip netns add $NSE
ip link add va netns $NSA type veth peer name ea netns $NSE
ip link add vb netns $NSB type veth peer name eb netns $NSE
ip -n $NSA addr add 10.0.0.1/24 dev va; ip -n $NSB addr add 10.0.0.2/24 dev vb
for x in "$NSA va" "$NSB vb" "$NSE ea" "$NSE eb"; do read n d <<< "$x"; ip -n $n link set $d up; offloads $n $d tx off; done
emulate() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=()
	ip netns exec $NSE python3 "$TOP/tests/link-emulator.py" ea eb 1 --a2b "$1" --b2a "rate=100m" 2>"$T/emu.log" &
	PIDS+=($!); sleep 1
}
emulate "rate=20m,limit=100"
attach $NSA va --capacity-window 6s; attach $NSB vb
ip netns exec $NSA ping -c 3 -q 10.0.0.2 >/dev/null 2>&1
# rate of what the emulator delivered: 20 Mbit/s of frames = 20 * 1228 / 1242 of IP
udp_blast $NSA 10.0.0.2 30 8
CAP=$(kv $NSA capacity_kbps); LOSS=$(kv $NSA loss_pct)
check "linkcap emulated 20M, sent 30M: at capacity" eval '[ "$(kv $NSA congested)" -ge 10 ]'
check "linkcap emulated 20M, sent 30M: capacity ~19.8M (got $CAP kbit/s)" between "$CAP" 15000 21000
check "linkcap emulated 20M, sent 30M: loss ~34 % (got $LOSS)" between "$LOSS" 25 42
sleep 7
udp_blast $NSA 10.0.0.2 10 8
LB=$(kv $NSA lower_bound_kbps)
check "linkcap emulated 20M, sent 10M: state under" eval '[ "$(kv $NSA state)" = under ] && [ "$(kv $NSA capacity_kbps)" = - ]'
check "linkcap emulated 20M, sent 10M: lower bound ~10M (got $LB kbit/s)" between "$LB" 8500 12000
emulate "loss=5"
sleep 7
udp_blast $NSA 10.0.0.2 5 8
LOSS=$(kv $NSA loss_pct)
check "linkcap emulated 5 % loss: measured (got $LOSS)" between "$LOSS" 3 7.5
check "linkcap emulated 5 % loss: not taken for congestion" eval '[ "$(kv $NSA congested)" -eq 0 ] && [ "$(kv $NSA state)" = under ]'

# ------------------------------------------------------------ point-to-point (tun)
reset_ns
relay() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=()
	python3 "$TOP/tests/linkcap-tun-relay.py" $NSA ta $NSB tb --a2b "$1" >"$T/relay.out" 2>&1 &
	PIDS+=($!)
	for i in $(seq 50); do grep -q ready "$T/relay.out" && break; sleep 0.1; done
}
relay "rate=8m,limit=60"
ip -n $NSA addr add 10.1.0.1 peer 10.1.0.2 dev ta; ip -n $NSB addr add 10.1.0.2 peer 10.1.0.1 dev tb
ip -n $NSA link set ta up; ip -n $NSB link set tb up
check "linkcap p2p: programs load (A)" attach $NSA ta --capacity-window 6s
check "linkcap p2p: programs load (B)" attach $NSB tb
check "linkcap p2p: detected as point-to-point" grep -q "link=p2p" "$T/cfg-$NSA/ta/egress/60000.bpfc"
ip netns exec $NSA ping -c 20 -i 0.05 -q 10.1.0.2 >/dev/null 2>&1
check "linkcap p2p: one neighbor (peer), answered" eval '[ "$(kv $NSA neighbor)" = peer ] && [ "$(ctr $NSA replies_received)" -ge 3 ]'
check "linkcap p2p: counts agree" eval '[ "$(kv $NSA tx_packets)" -eq "$(kv $NSB rx_packets)" ]'
udp_blast $NSA 10.1.0.2 12 8
CAP=$(kv $NSA capacity_kbps)
check "linkcap p2p 8M, sent 12M: at capacity" eval '[ "$(kv $NSA congested)" -ge 5 ]'
check "linkcap p2p 8M, sent 12M: capacity (got $CAP kbit/s)" between "$CAP" 5000 8500

for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=()
tests_exit
