#!/bin/bash
#
# The flow monitor (programs/flowmon): its TC program on both hooks of lo, in a
# new network and mount namespace, and bpfc-flows reading the maps.
#
#   bash tests/test-flowmon.sh
#
# Crafted TCP segments (tests/flowmon-send.py) check the retransmission and loss
# classification: one flow per case, so the cases do not disturb each other.
# On lo every packet passes egress and then ingress, both on ifindex 1.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root flowmon
require_cmds flowmon python3 unshare mount
TOP=$PWD
BPFC=$TOP/bpfc
[ -x "$BPFC" ] || { test_fail "flowmon (bpfc not built: make)"; tests_exit; }

if [ -z "${FLOWMON_TEST_NS:-}" ]; then
	rm -f "$TESTS_FAILED_FILE"
	FLOWMON_TEST_NS=1 exec unshare --net --mount bash "$0" "$@"
fi

T=$(mktemp -d /tmp/bpfc-flowmon.XXXXXX)
trap 'umount "$T/bpf" 2>/dev/null; rm -rf "$T"; rm -f "$TESTS_FAILED_FILE"' EXIT
EX="$TOP/programs/flowmon/examples/interfaces.d/%all%"
FLOWS=$TOP/programs/flowmon/bpfc-flows
SEND="python3 $TOP/tests/flowmon-send.py"

python3 "$TOP/tests/flowmon-send.py" --lo-up || { test_fail "flowmon (cannot bring lo up)"; tests_exit; }
mkdir -p "$T/bpf" && mount -t bpf bpf "$T/bpf" || { test_fail "flowmon (cannot mount bpffs)"; tests_exit; }

for d in ingress egress; do
	check "flowmon $d program loads on lo" eval '"$BPFC" -m "$T/bpf" -i lo -d $d -p 10 -f "$EX/$d/10.bpfc" >"$T/$d.log" 2>&1'
done
check "flowmon egress uses the egress maps" test -e "$T/bpf/FM_TSEQ_E"
check "flowmon map sizes follow FM_FLOWS"       eval '"$BPFC" -m "$T/bpf" -T -i lo -s FM_FLOWS=64 -f "$EX/ingress/10.bpfc" 2>&1 | grep -q "FM_LAST'"'"' is pinned with 10000 entries, declared with 64" && "$BPFC" -m "$T/bpf" -T -i lo -s FM_FLOWS=64 -f "$EX/ingress/10.bpfc" 2>&1 | grep -q "FM_TSEQ_I'"'"' is pinned with 20000 entries, declared with 128"'
check "flowmon uses 16 maps per hook" eval '[ "$(ls "$T/bpf" | grep -c "^FM_.*_I$")" -eq 12 ] && [ "$(ls "$T/bpf" | grep -c "^FM_[A-Z]*$")" -eq 4 ]'

flows() { BPFC_BIN=$BPFC "$FLOWS" -m "$T/bpf" --state "$T/state" --active 0 "$@"; }
# field <flow src> <sport> <field>: the field of that flow in --json output
field() {
	python3 -c 'import json, sys
for r in json.load(open(sys.argv[1])):
    if r["src"] == sys.argv[2] and r["sport"] == int(sys.argv[3]):
        print("null" if r[sys.argv[4]] is None else r[sys.argv[4]]); break
else: print("missing")' "$T/out.json" "$1" "$2" "$3"
}
is() { local v; v=$(field "$1" "$2" "$3"); [ "$v" = "$4" ] || { echo "  $3 of $1:$2 is $v, expected $4"; return 1; }; }

flows --json >/dev/null      # first sample

A=127.0.0.1
# 1: in order, then a duplicate of seen data: one retransmission downstream
$SEND 127.0.0.11 1001 $A 80 1000 100 1100 100 1100 100
# 2: a hole of 100 bytes never filled: upstream loss
$SEND 127.0.0.12 1002 $A 80 1000 100 1200 100 1300 100
# 3: a hole filled 2 ms later (reordering): no loss, no retransmission
$SEND 127.0.0.13 1003 $A 80 1000 100 1200 100 1100 100
# 4: a hole filled 60 ms later: retransmission repairing upstream loss
$SEND 127.0.0.14 1004 $A 80 1000 100 1200 100 +60 1100 100
# 5: sequence numbers wrapping past 2^32, in order
$SEND 127.0.0.15 1005 $A 80 0xffffff00 0x80 0xffffff80 0x100 0x80 0x80
# 6: the reverse direction is counted apart
$SEND 127.0.0.16 1006 $A 80 5000 100
$SEND $A 80 127.0.0.16 1006 9000 50 9000 50
sleep 0.2
flows --json > "$T/out.json"
check "flowmon --json is valid JSON"            python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$T/out.json"
check "flowmon counts packets on both hooks"     eval '[ "$(field 127.0.0.11 1001 packets_in)" -ge 3 ] && [ "$(field 127.0.0.11 1001 packets_in)" = "$(field 127.0.0.11 1001 packets_out)" ]'
check "flowmon payload bytes per direction"     is 127.0.0.11 1001 tcp_fwd_data_bytes 300
check "flowmon duplicate is a retransmission"   eval 'is 127.0.0.11 1001 tcp_fwd_retrans_pkts 1 && is 127.0.0.11 1001 tcp_fwd_loss_events 0'
check "flowmon retransmission percentage"       is 127.0.0.11 1001 tcp_fwd_retrans_pct 33.33
check "flowmon hole is upstream loss"           eval 'is 127.0.0.12 1002 tcp_fwd_loss_events 1 && is 127.0.0.12 1002 tcp_fwd_loss_bytes 100 && is 127.0.0.12 1002 tcp_fwd_retrans_pkts 0'
check "flowmon loss percentage"                 is 127.0.0.12 1002 tcp_fwd_loss_pct 25.0
check "flowmon reordering is not loss"          eval 'is 127.0.0.13 1003 tcp_fwd_loss_events 0 && is 127.0.0.13 1003 tcp_fwd_loss_bytes 0 && is 127.0.0.13 1003 tcp_fwd_retrans_pkts 0'
check "flowmon late fill is a retransmission"   eval 'is 127.0.0.14 1004 tcp_fwd_retrans_pkts 1 && is 127.0.0.14 1004 tcp_fwd_loss_bytes 100'
check "flowmon sequence wraparound"             eval 'is 127.0.0.15 1005 tcp_fwd_retrans_pkts 0 && is 127.0.0.15 1005 tcp_fwd_loss_events 0 && is 127.0.0.15 1005 tcp_fwd_data_bytes 512'
check "flowmon reverse direction apart"         eval 'is 127.0.0.16 1006 tcp_rev_retrans_pkts 1 && is 127.0.0.16 1006 tcp_fwd_retrans_pkts 0 && is 127.0.0.16 1006 tcp_rev_data_bytes 100'

# Second sample of the same flows: rates and current percentages
$SEND 127.0.0.11 1001 $A 80 1200 100 1200 100
flows --json > "$T/out.json"
check "flowmon rates since the previous sample" eval '[ "$(field 127.0.0.11 1001 sample_seconds)" != null ] && [ "$(field 127.0.0.11 1001 bps_in)" -gt 0 ]'
check "flowmon current retransmissions"         eval 'is 127.0.0.11 1001 tcp_fwd_retrans_pkts_now 1 && is 127.0.0.11 1001 tcp_fwd_retrans_pct_now 50.0 && is 127.0.0.11 1001 tcp_retrans_pkts 2'

check "flowmon --csv header matches --json"     eval '[ "$(flows --csv | head -1)" = "$(python3 -c "import json,sys; print(\",\".join(json.load(open(sys.argv[1]))[0]))" "$T/out.json")" ]'
check "flowmon --csv has a line per flow"       eval '[ $(( $(flows --csv | wc -l) - 1 )) -eq $(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$T/out.json") ]'
check "flowmon table filter and sort"           eval 'flows -t --filter src=127.0.0.0/24 --filter min-retrans=1 --sort retrans > "$T/table" && grep -q "^127.0.0.11 " "$T/table" && ! grep -q "^127.0.0.13 " "$T/table" && grep -q "^Flows: " "$T/table"'
check "flowmon bad filter is refused"           eval '! flows --filter nosuch=1 >/dev/null 2>&1'

tests_exit
