#!/bin/bash
#
# Integration test for bpfcd and bpfcctl.
#
# Runs bpfcd against a throwaway config tree and checks the kernel with `tc`
# after each scenario. Creates and deletes veth pairs named bpfctA/bpfctB.
#
#   sh tests/test-bpfcd.sh [-d] [-k]     -d: show daemon log on failure, -k: keep temp dir
#
# Must be run as root from the repository root after `make`.

if [ "$(id -u)" != "0" ]; then
	echo "Must be run as root"
	exit 1
fi

DEBUG=0
KEEP=0
for a in "$@"; do
	[ "$a" = "-d" ] && DEBUG=1
	[ "$a" = "-k" ] && KEEP=1
done

RED='\e[31m'; GREEN='\e[32m'; NC='\e[0m'
TOP=$(cd "$(dirname "$0")/.." && pwd)
BPFC=$TOP/bpfc
BPFCD=$TOP/bpfcd/bpfcd
BPFCCTL=$TOP/bpfcd/bpfcctl
for b in "$BPFC" "$BPFCD" "$BPFCCTL"; do
	[ -x "$b" ] || { echo "$b not built; run make first"; exit 1; }
done

T=$(mktemp -d /tmp/bpfcd-test.XXXXXX)
CFG=$T/etc/interfaces.d
A=bpfctA
B=bpfctB
PASS=0
FAIL=0
DPID=

cleanup() {
	[ -n "$DPID" ] && kill "$DPID" 2>/dev/null && wait "$DPID" 2>/dev/null
	ip link del $A 2>/dev/null
	ip link del $B 2>/dev/null
	[ $KEEP -eq 1 ] && echo "kept $T" || rm -rf "$T"
}
trap cleanup EXIT

ok()   { echo -e "  $* ${GREEN}PASS${NC}"; PASS=$((PASS + 1)); }
bad()  {
	echo -e "  $* ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
	if [ $DEBUG -eq 1 ]; then echo "---- daemon log (tail)"; tail -20 "$T/log"; echo "----"; fi
}
check() { local name="$1"; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

# prog id attached at IFACE DIR PRIO, empty when none
prog_at() { tc filter show dev "$1" "$2" pref "$3" 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
# status field of a slot in the state file
status_of() {
	awk -v i="$1" -v d="$2" -v p="$3" '$1=="slot" {
		delete kv; for (n = 2; n <= NF; n++) { split($n, x, "="); kv[x[1]] = x[2] }
		if (kv["iface"] == i && kv["dir"] == d && kv["prio"] == p) print kv["status"] }' "$T/run/state"
}
reload_count() { sed -n 's/.* reload_count=\([0-9]*\).*/\1/p' "$T/run/state"; }
# retry a condition for up to ~5s (the daemon reacts asynchronously)
eventually() { for _ in $(seq 50); do "$@" && return 0; sleep 0.1; done; return 1; }
has_prog()  { [ -n "$(prog_at "$1" "$2" "$3")" ]; }
no_prog()   { [ -z "$(prog_at "$1" "$2" "$3")" ]; }
is_status() { [ "$(status_of "$1" "$2" "$3")" = "$4" ]; }
same_id()   { [ "$(prog_at "$1" "$2" "$3")" = "$4" ]; }
diff_id()   { local c; c=$(prog_at "$1" "$2" "$3"); [ -n "$c" ] && [ "$c" != "$4" ]; }

write_conf() {
	cat > "$T/etc/bpfc.conf" <<-EOF
	bpfc_path = $BPFC
	config_dir = $CFG
	state_dir = $T/run
	on_external_change = ${1:-reinstall}
	remove_on_stop = ${2:-no}
	reinstall_limit = ${3:-5}
	EOF
}
start_daemon() { $BPFCD -c "$T/etc/bpfc.conf" >> "$T/log" 2>&1 & DPID=$!; eventually test -s "$T/run/state"; }
stop_daemon()  { kill "$DPID"; wait "$DPID" 2>/dev/null; DPID=; }
# SIGHUP and wait until the daemon reports the rescan finished
reload() { $BPFCCTL -c "$T/etc/bpfc.conf" reload >/dev/null; }

ip link del $A 2>/dev/null; ip link del $B 2>/dev/null
mkdir -p "$CFG/$A/ingress" "$CFG/$A/egress" "$CFG/$B/ingress" "$T/run"
printf '# drop tcp\nmatch tcp;\n\tdrop\n' > "$CFG/$A/ingress/10.bpfc"
printf 'match udp; drop\n'                > "$CFG/$A/ingress/20.bpfc"
printf 'match icmp; drop\n'               > "$CFG/$A/egress/10.bpfc"
printf 'match arp; drop\n'                > "$CFG/$B/ingress/5.bpfc"
printf 'bogus-instruction 1\n'            > "$CFG/$A/egress/30.bpfc"
printf 'match tcp; drop\n'                > "$CFG/$A/ingress/010.bpfc"   # invalid name: ignored
write_conf
ip link add $A type veth peer name ${A}p

echo "startup"
start_daemon
check "programs installed on existing interface" eventually has_prog $A ingress 10
check "ingress 20 and egress 10 installed"     eval 'has_prog $A ingress 20 && has_prog $A egress 10'
check "missing interface is pending"           is_status $B ingress 5 pending-iface
check "compile error marked failed"            is_status $A egress 30 failed
check "failed priority left empty"             no_prog $A egress 30
check "error log saved"                        test -s "$T/run/errors/$A.egress.30.log"
check "leading-zero file name ignored"         eval '! grep -q "prio=10 path=[^ ]*/010.bpfc" $T/run/state'
check "filter carries bpfcd name"              eval 'tc filter show dev $A ingress | grep -q "bpfcd:$A/ingress/10"'
check "bpfcctl status exits 2 (a failure)"     eval '$BPFCCTL -s $T/run status >/dev/null; [ $? -eq 2 ]'
# Non-root users must see a root-owned daemon as running (kill(pid, 0) gives EPERM, not ESRCH).
if id nobody >/dev/null 2>&1; then
	chmod 755 "$T"
	install -m 0755 "$BPFCCTL" "$T/bpfcctl"
	check "non-root status sees daemon running"  eval 'su -s /bin/sh nobody -c "$T/bpfcctl -s $T/run status" >/dev/null 2>&1; [ $? -eq 2 ]'
fi

echo "interface events"
ip link add $B type veth peer name ${B}p
check "program installed when interface created" eventually has_prog $B ingress 5
check "status becomes installed"               eventually is_status $B ingress 5 installed
ip link del $B
check "interface removal -> pending"           eventually is_status $B ingress 5 pending-iface
ip link add $B type veth peer name ${B}p
check "re-created interface reinstalled"       eventually has_prog $B ingress 5

echo "reload"
ID10=$(prog_at $A ingress 10)
ID20=$(prog_at $A ingress 20)
sleep 0.05; touch "$CFG/$A/ingress/10.bpfc"; reload
check "touch only (same hash) keeps program"   same_id $A ingress 10 "$ID10"
printf 'match udp; match udp-dst 53; drop\n' > "$CFG/$A/ingress/20.bpfc"; reload
check "changed file replaced in place"         diff_id $A ingress 20 "$ID20"
check "unchanged file kept"                    same_id $A ingress 10 "$ID10"
rm "$CFG/$A/egress/10.bpfc"; reload
check "deleted file detached"                  no_prog $A egress 10
check "other priorities untouched"             same_id $A ingress 10 "$ID10"
printf 'match ip6; drop\n' > "$CFG/$A/egress/40.bpfc"; reload
check "new file installed"                     has_prog $A egress 40
printf 'match tcp; drop\n' > "$CFG/$A/egress/30.bpfc"; reload
check "fixed file installs on reload"          is_status $A egress 30 installed
ID20=$(prog_at $A ingress 20)
printf 'start-loop; loop-reg\n' > "$CFG/$A/ingress/20.bpfc"; reload
check "verifier rejection marked failed"       is_status $A ingress 20 failed
check "old program removed, not kept"          no_prog $A ingress 20
check "verifier reason recorded"               eval 'grep -q "error=verifier%20rejected%20program:%20R7%20!read_ok" $T/run/state'
check "bpfcctl show prints failure output"     eval '$BPFCCTL -s $T/run show $A ingress 20 | grep -q "VERIFIER REJECTION"'
printf 'match udp; drop\n' > "$CFG/$A/ingress/20.bpfc"; reload

echo "external changes (reinstall policy)"
ID10=$(prog_at $A ingress 10)
tc filter del dev $A ingress pref 10
check "externally removed program reinstalled" eventually diff_id $A ingress 10 "$ID10"
ID10=$(prog_at $A ingress 10)
$BPFC -i $A -d ingress -p 10 "match arp; drop" >/dev/null
check "externally replaced program restored"   eventually eval 'diff_id $A ingress 10 $ID10 && tc filter show dev $A ingress pref 10 | grep -q bpfcd:'
tc qdisc del dev $A clsact
check "clsact deletion restores all programs"  eventually eval 'has_prog $A ingress 10 && has_prog $A ingress 20 && has_prog $A egress 30 && has_prog $A egress 40'
$BPFC -i $A -d ingress -p 77 "match arp; drop" >/dev/null
sleep 0.5
check "unmanaged priority left alone"          has_prog $A ingress 77
check "bpfcctl status -a lists unmanaged"      eval '$BPFCCTL -s $T/run status -a | grep -Eq "^$A +ingress +77 "'
$BPFC -i $A -d ingress -p 77 -D

echo "external changes (log policy)"
write_conf log; reload
ID10=$(prog_at $A ingress 10)
tc filter del dev $A ingress pref 10
check "removal logged, not reinstalled"        eventually is_status $A ingress 10 removed-externally
sleep 0.4
check "priority stays empty"                   no_prog $A ingress 10
$BPFC -i $A -d ingress -p 20 "match arp; drop" >/dev/null
check "replacement logged"                     eventually is_status $A ingress 20 replaced-externally
reload
check "reload restores logged slots"           eval 'has_prog $A ingress 10 && is_status $A ingress 20 installed'

echo "reinstall limit"
write_conf reinstall no 2; reload
for _ in 1 2 3 4; do tc filter del dev $A ingress pref 10 2>/dev/null; sleep 0.4; done
check "gives up after reinstall_limit"         eventually is_status $A ingress 10 reinstall-limit
reload
check "reload re-arms it"                      eventually has_prog $A ingress 10

echo "restart"
write_conf; reload
ID10=$(prog_at $A ingress 10); ID40=$(prog_at $A egress 40)
stop_daemon
check "programs stay attached after stop"      same_id $A ingress 10 "$ID10"
rm "$CFG/$A/egress/40.bpfc"
start_daemon
check "running programs adopted, not reloaded" eventually same_id $A ingress 10 "$ID10"
check "file deleted while stopped is removed"  eventually no_prog $A egress 40
check "bpfcctl show --bytecode disassembles"   eval '$BPFCCTL -s $T/run show $A/ingress/10 --bytecode | grep -q "exit"'
stop_daemon
write_conf reinstall yes
start_daemon
stop_daemon
check "remove_on_stop detaches everything"     eval 'no_prog $A ingress 10 && no_prog $A ingress 20 && no_prog $A egress 30'

echo
echo -e "bpfcd tests: ${GREEN}$PASS passed${NC}, $([ $FAIL -eq 0 ] && echo 0 || echo -e "${RED}$FAIL failed${NC}")"
[ $FAIL -eq 0 ]
