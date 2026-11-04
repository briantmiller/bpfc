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
	ip netns del bpfctN 2>/dev/null
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

echo "includes"
mkdir -p "$T/lib"
printf 'define block-proto P;\n  match $P; drop; end-match;\nend-define;\n' > "$T/lib/blk.bpfc"
printf 'include %s/lib/blk.bpfc;\nblock-proto tcp\n' "$T" > "$CFG/$A/egress/50.bpfc"; reload
check "program with include installed"         is_status $A egress 50 installed
ID50=$(prog_at $A egress 50)
reload
check "unchanged include keeps program"        same_id $A egress 50 "$ID50"
printf 'define block-proto P;\n  match $P; match tcp-dst 23; drop; end-match; end-match;\nend-define;\n' > "$T/lib/blk.bpfc"
check "bpfcctl sees the changed include"       eval '$BPFCCTL -s $T/run status | grep -E "^$A +egress +50 " | grep -q "modified, reload pending"'
reload
check "changed include replaces program"       diff_id $A egress 50 "$ID50"
check "bpfcctl: no change after reload"        eval '! $BPFCCTL -s $T/run status | grep -E "^$A +egress +50 " | grep -q "modified, reload pending"'
chmod o+w "$T/lib/blk.bpfc"; printf '# touched\n' >> "$T/lib/blk.bpfc"; reload
check "world-writable include refused"         is_status $A egress 50 failed
rm "$CFG/$A/egress/50.bpfc"; chmod o-w "$T/lib/blk.bpfc"; reload

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

echo "templates: %all% and %<kind>% (own network namespace)"
# In a namespace so that %all% never touches the host's real interfaces.
NS=bpfctN
T2=$T/ns
CFG2=$T2/etc/interfaces.d
nx() { ip netns exec $NS "$@"; }
nprog_at() { nx tc filter show dev "$1" "$2" pref "$3" 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
nfield() {   # nfield <iface> <dir> <prio> <key>: a field of the slot in the namespace's state
	awk -v i="$1" -v d="$2" -v p="$3" -v k="$4" '$1=="slot" {
		delete kv; for (n = 2; n <= NF; n++) { split($n, x, "="); kv[x[1]] = x[2] }
		if (kv["iface"] == i && kv["dir"] == d && kv["prio"] == p) print kv[k] }' "$T2/run/state"
}
nhas()    { [ -n "$(nprog_at "$1" "$2" "$3")" ]; }
nnone()   { [ -z "$(nprog_at "$1" "$2" "$3")" ]; }
nfrom()   { nfield "$1" "$2" "$3" path | sed 's/%25/%/g' | grep -q -- "$4"; }   # the state file encodes %
nstat()   { [ "$(nfield "$1" "$2" "$3" status)" = "$4" ]; }
nslot()   { [ -n "$(nfield "$1" "$2" "$3" status)" ]; }
nreload() { $BPFCCTL -c "$T2/etc/bpfc.conf" reload >/dev/null; }

ip netns del $NS 2>/dev/null
ip netns add $NS
nx ip link set lo up
nx ip link add v0 type veth peer name v1
nx ip link add vx0 type vxlan id 7 dstport 4789
nx ip tuntap add dev tun0 mode tun
mkdir -p "$CFG2/%all%/ingress" "$CFG2/%all%/egress" "$T2/run"
printf 'bpfc_path = %s\nconfig_dir = %s\nstate_dir = %s\n' "$BPFC" "$CFG2" "$T2/run" > "$T2/etc/bpfc.conf"
printf 'match tcp; match tcp-dst 9; drop\n' > "$CFG2/%all%/ingress/100.bpfc"
# compiled per interface: drops TCP on vxlan only (seen in the instruction count)
printf 'when $IFKIND == vxlan; match tcp; drop; otherwise; continue; end-when\n' > "$CFG2/%all%/egress/10.bpfc"
nx $BPFCD -c "$T2/etc/bpfc.conf" >> "$T/log" 2>&1 & NPID=$!
eventually test -s "$T2/run/state"
check "%all% installed on veth, vxlan and lo"    eventually eval 'nhas v0 ingress 100 && nhas v1 ingress 100 && nhas vx0 ingress 100 && nhas lo ingress 100'
check "%all% also covers a raw-IP device (tun)"   eval 'nhas tun0 ingress 100 && nfrom tun0 ingress 100 %all%'
check "filter named for the interface"           eval 'nx tc filter show dev vx0 ingress | grep -q "bpfcd:vx0/ingress/100"'
check "\$IFKIND compiled per interface"           eval '[ "$(nfield vx0 egress 10 insns)" -gt "$(nfield v0 egress 10 insns)" ]'
# Ethernet fields: fails to compile on the tun only
printf 'match arp; drop\n' > "$CFG2/%all%/egress/20.bpfc"; nreload
check "Ethernet-only template: failed on tun only" eval 'nstat tun0 egress 20 failed && nhas v0 egress 20 && nhas vx0 egress 20'
printf 'when $L3OFF == 14; match arp; drop; end-when\n' > "$CFG2/%all%/egress/20.bpfc"; nreload
check "...guarded with \$L3OFF it installs everywhere" eval 'nstat tun0 egress 20 installed && nhas tun0 egress 20 && nhas v0 egress 20'
rm "$CFG2/%all%/egress/20.bpfc"; nreload
check "bpfcd -t lists the expansion"             eval 'nx $BPFCD -c $T2/etc/bpfc.conf -t | grep -E "^ +vx0 +ingress +prio 100 " | grep -q "%all%"'

mkdir -p "$CFG2/%tun%/ingress" "$CFG2/%veth%/ingress" "$CFG2/%vxlan%/ingress" "$CFG2/v1/ingress" "$CFG2/v0/ingress"
printf 'continue\n' > "$CFG2/%tun%/ingress/100.bpfc"
ID_V0=$(nprog_at v0 ingress 100); ID_VX=$(nprog_at vx0 ingress 100)
printf 'match udp; match udp-dst 9; drop\n' > "$CFG2/%veth%/ingress/100.bpfc"; nreload
check "%tun% applies to the tun device"          eval 'nhas tun0 ingress 100 && nfrom tun0 ingress 100 %tun%'
check "%veth% overrides %all% on veths"          eval 'nfrom v0 ingress 100 %veth% && [ "$(nprog_at v0 ingress 100)" != "$ID_V0" ]'
check "vxlan keeps the %all% program"            eval 'nfrom vx0 ingress 100 %all% && [ "$(nprog_at vx0 ingress 100)" = "$ID_VX" ]'
: > "$CFG2/v1/ingress/100.bpfc"; nreload
check "empty interface file excludes"            eval 'nstat v1 ingress 100 excluded && nnone v1 ingress 100'
: > "$CFG2/%vxlan%/ingress/100.bpfc"; nreload
check "empty %kind% file excludes %all%"         eval 'nstat vx0 ingress 100 excluded && nnone vx0 ingress 100 && nhas lo ingress 100'
ID_V0=$(nprog_at v0 ingress 100)
printf 'match icmp; drop\n' > "$CFG2/v0/ingress/100.bpfc"
printf 'match arp; drop\n'  > "$CFG2/v0/ingress/50.bpfc"; nreload
check "interface file overrides %kind%"          eval 'nfrom v0 ingress 100 /v0/ && [ "$(nprog_at v0 ingress 100)" != "$ID_V0" ]'
check "other priorities coexist"                 eval 'nhas v0 ingress 50 && nhas v0 egress 10'
rm "$CFG2/v0/ingress/100.bpfc"; nreload
check "removing it falls back to %kind%"         eval 'nfrom v0 ingress 100 %veth% && nhas v0 ingress 100'
rm "$CFG2/%vxlan%/ingress/100.bpfc"; nreload
check "removing the exclusion reinstalls"        eventually eval 'nhas vx0 ingress 100 && nstat vx0 ingress 100 installed'
check "bpfcctl status shows excluded slots"      eval '$BPFCCTL -s $T2/run status | grep -E "^v1 +ingress +100 " | grep -q excluded'
ID_VX=$(nprog_at vx0 ingress 100); ID_TUN=$(nprog_at tun0 ingress 100)
kill $NPID; wait $NPID 2>/dev/null
nx $BPFCD -c "$T2/etc/bpfc.conf" >> "$T/log" 2>&1 & NPID=$!
check "restart adopts template programs"         eventually eval '[ "$(nprog_at vx0 ingress 100)" = "$ID_VX" ] && [ "$(nprog_at tun0 ingress 100)" = "$ID_TUN" ] && nstat vx0 ingress 100 installed'
check "...and keeps the exclusion"               eval 'nstat v1 ingress 100 excluded && nnone v1 ingress 100'

nx ip link add v2 type veth peer name v3
check "new interface gets template programs"     eventually eval 'nhas v2 ingress 100 && nfrom v2 ingress 100 %veth% && nhas v3 egress 10'
nx ip link del v2
check "deleted interface's slots dropped"        eventually eval '! nslot v2 ingress 100 && ! nslot v3 egress 10'
nx ip link del v0
check "...an interface's own file stays pending" eventually nstat v0 ingress 50 pending-iface
nx ip link set vx0 down; nx ip link set vx0 name vx9
check "renamed interface: programs follow"       eventually eval 'nhas vx9 ingress 100 && ! nslot vx0 ingress 100'
kill $NPID; wait $NPID 2>/dev/null
ip netns del $NS

echo
echo -e "bpfcd tests: ${GREEN}$PASS passed${NC}, $([ $FAIL -eq 0 ] && echo 0 || echo -e "${RED}$FAIL failed${NC}")"
[ $FAIL -eq 0 ]
