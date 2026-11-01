#!/bin/bash
# Collect what is needed to debug a failing satellite (800 ms) test.
#
#   sudo bash tests/test-dataplane.sh -k        # keep namespaces and emulator
#   sudo bash tests/collect-dataplane-debug.sh > dataplane-debug.txt 2>&1
#
# Repeats the 2 MB TCP copy over the emulated link and prints versions,
# interface settings, kernel TCP counters and the dataplane state.

cd "$(dirname "$0")/.." || exit 1
BPFC=$PWD/bpfc
MAPS=/run/bpfc-dp-test
CONF=/tmp/bpfc-dp-test
NSA=dpta; NSB=dptb; NSM=dptm
A() { ip netns exec $NSA "$@"; }
B() { ip netns exec $NSB "$@"; }
sec() { echo; echo "===== $*"; }

ip netns list | grep -q "^$NSM" || { echo "test namespaces not found: run 'bash tests/test-dataplane.sh -k' first"; exit 1; }

sec versions
uname -r; cat /etc/redhat-release 2>/dev/null || head -2 /etc/os-release
python3 --version; nc --version 2>&1 | head -1; nc -h 2>&1 | grep -c -- --send-only | sed 's/^/nc has --send-only: /'
iperf3 --version 2>&1 | head -1; $BPFC -h 2>/dev/null | head -1

sec emulator
pgrep -af "link-emulator.py" || echo "EMULATOR NOT RUNNING"
tail -2 $CONF/emulator.log 2>/dev/null
sysctl net.core.rmem_max net.core.wmem_max; nproc
[ -f /tmp/bpfc-dp-rx15.bin ] && { echo "15 MB test failure kept:"; ls -la /tmp/bpfc-dp-tx15.bin /tmp/bpfc-dp-rx15.bin; cmp -l /tmp/bpfc-dp-tx15.bin /tmp/bpfc-dp-rx15.bin 2>/dev/null | head -20; }

sec "interfaces (A side)"
A ip -d link show dps0 | grep -oE "mtu [0-9]+|gso_max_segs [0-9]+|gso_max_size [0-9]+|gro_max_size [0-9]+"
A ip route show dev dps0
A ethtool -k dps0 | grep -E "^(rx-checksumming|tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|scatter-gather):"
B ip -d link show dps1 | grep -oE "mtu [0-9]+|gso_max_segs [0-9]+"
ip netns exec $NSM ethtool -k dpm0 | grep -E "^(rx-checksumming|tx-checksumming|generic-receive-offload|generic-segmentation-offload):"
A tc filter show dev dps0 egress | grep -c jited | sed 's/^/egress programs: /'
A tc filter show dev dps0 ingress | grep -c jited | sed 's/^/ingress programs: /'
A tc qdisc show dev dps0

tcpstat() {   # tcpstat <ns>: nonzero TCP and TcpExt counters
    ip netns exec $1 awk '
        /^(Tcp|TcpExt|IpExt|Ip):/ { if (!(($1) in hdr)) { hdr[$1] = $0; next }
            n = split(hdr[$1], h); split($0, v)
            for (i = 2; i <= n; i++) if (v[i] != 0 && h[i] !~ /^(RtoAlgorithm|RtoMin|RtoMax|MaxConn|Forwarding|DefaultTTL)$/) printf "%s%s=%s ", $1, h[i], v[i]
            print "" }' /proc/net/snmp /proc/net/netstat
}

sec "TCP copy over the emulated link"
before_a=$(tcpstat $NSA); before_b=$(tcpstat $NSB)
if nc -h 2>&1 | grep -q -- '--send-only'; then NC_SEND="nc --send-only"; else NC_SEND="nc -N"; fi
head -c 2000000 /dev/urandom > $CONF/dbg-tx.bin; rm -f $CONF/dbg-rx.bin
B timeout 90 nc -l -p 5099 > $CONF/dbg-rx.bin & rp=$!
sleep 0.5
start=$(date +%s.%N)
A timeout 90 $NC_SEND 10.77.2.2 5099 < $CONF/dbg-tx.bin; echo "sender exit status $?"
wait $rp; echo "receiver exit status $?"
end=$(date +%s.%N)
echo "took $(echo "$end - $start" | bc) s; received $(stat -c %s $CONF/dbg-rx.bin) of 2000000 bytes"
cmp $CONF/dbg-tx.bin $CONF/dbg-rx.bin && echo "contents intact"
echo "first test run: received $(stat -c %s $CONF/rx2.bin 2>/dev/null || echo '?') of 2000000 bytes"; cmp $CONF/tx2.bin $CONF/rx2.bin 2>&1 | head -1

sec "TCP counters, before and after the copy"
echo "A before: $before_a"; echo "A after:  $(tcpstat $NSA)"
echo "B before: $before_b"; echo "B after:  $(tcpstat $NSB)"

sec "ping through the dataplane"
A ping -c 3 -W 3 -q 10.77.2.2 | tail -2
A ping -c 2 -W 3 -s 1464 -M do -q 10.77.2.2 | tail -2

sec "dataplane status"
for x in "$NSA dps0" "$NSB dps1"; do
    set -- $x
    env BPFC=$BPFC dataplane/bpfc-dataplane-status -m $MAPS -c $CONF/$1 $2
    env BPFC=$BPFC dataplane/bpfc-dataplane-status -m $MAPS -c $CONF/$1 -1 $2
done

sec "raw counters"
P0=$(dataplane/bpfc-dataplane-gen -i dps0 --map-prefix); P1=$(dataplane/bpfc-dataplane-gen -i dps1 --map-prefix)
for m in ${P0}_tx ${P0}_rx ${P1}_tx ${P1}_rx; do
    printf "%s: " $m
    $BPFC -m $MAPS -r $m 2>&1 | while read -r _ _ k _ _ v; do
        [[ "$k" == 0x* ]] && printf "%d=%d " $((16#${k#0x})) $((16#${v#0x}))
    done
    echo
done

sec "kernel log"
dmesg 2>/dev/null | tail -20
