#!/bin/bash
#
# Frontends: bpfc runs the program that translates a file type into bpfc
# (20.<type> -> /etc/bpfc/frontends/<type> or /usr/libexec/bpfc/frontends/<type>),
# and bpfcd manages such files like .bpfc ones: change detection (depends),
# conflicts, on-failure keep|remove, meta lines and bpfcctl show --source.
# Uses a shell frontend for the made-up type "upper".
#
#   tests/test-frontends.sh          (root)

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root frontends
require_cmds frontends ip tc

BPFC=$PWD/bpfc
BPFCD=$PWD/bpfcd/bpfcd
BPFCCTL=$PWD/bpfcd/bpfcctl
T=$(mktemp -d /tmp/bpfc-fe.XXXXXX)
chmod 755 $T            # frontends run unprivileged
IF=bpfcfeA
DPID=

cleanup() {
	[ -n "$DPID" ] && kill $DPID 2>/dev/null && wait $DPID 2>/dev/null
	ip link del $IF 2>/dev/null
}
trap 'cleanup; rm -rf "$T" "$TESTS_FAILED_FILE"' EXIT
cleanup

mkdir -p $T/sys $T/etc $T/conf/interfaces.d/$IF/ingress $T/run
cat > $T/sys/upper <<'EOF'
#!/bin/sh
# lines: DROP-PORT <n>, FAIL, ENV, or anything else (a meta line)
echo "name upper $BPFC_IFNAME $BPFC_HOOK $BPFC_PRIO;"
[ -f "$BPFC_CONF_DIR/extra.txt" ] && echo "depends $BPFC_CONF_DIR/extra.txt;"
while read a b; do
	case $a in
	DROP-PORT) echo "match udp; match dst-port $b; drop; end-match; end-match;" ;;
	REMOVE) echo "option on-failure remove;" ;;
	FAIL) echo "$BPFC_FILE:1: told to fail" >&2; exit 2 ;;
	ENV) env | sort | sed -n 's/^\(BPFC_[A-Z0-9_]*\)=.*/meta env \1;/p'; echo "meta path $PATH;" ;;
	"") ;;
	*) echo "meta rule $a $b;" ;;
	esac
done < "$BPFC_FILE"
EOF
chmod 755 $T/sys/upper
export BPFC_FRONTEND_DIRS=$T/etc:$T/sys

ip link add $IF type veth peer name ${IF}p
ip link set $IF up

echo "== bpfc -f <file>.<type>"
printf 'DROP-PORT 53\nhello world\nENV\n' > $T/20.upper
check "compiles through the frontend" $BPFC -i $IF -T -f $T/20.upper
out=$($BPFC -i $IF -p 20 -I -f $T/20.upper 2>&1)
check "name from the frontend"   eval 'echo "$out" | grep -q "^BPFC_NAME upper $IF ingress 20$"'
check "meta lines"               eval 'echo "$out" | grep -q "^BPFC_META rule hello world$"'
for v in BPFC_FRONTEND_API BPFC_FILE BPFC_IFNAME BPFC_IFINDEX BPFC_HOOK BPFC_PRIO BPFC_CONF_DIR BPFC_MAP_DIR BPFC_BPFC BPFC_L3OFF; do
	check "frontend env has $v" eval 'echo "$out" | grep -q "^BPFC_META env $v$"'
done
check "clean environment: no BPFC_FRONTEND_DIRS" eval '! echo "$out" | grep -q "env BPFC_FRONTEND_DIRS"'
$BPFC -i $IF -p 20 -D >/dev/null 2>&1
check "-F bpfc treats the file as bpfc" eval '! $BPFC -i $IF -T -F bpfc -f $T/20.upper 2>/dev/null'
printf 'DROP-PORT 53\n' > $T/plain.txt
check "-F <type> for any file name" $BPFC -i $IF -T -F upper -f $T/plain.txt
check "-G writes the translation" eval '$BPFC -i $IF -T -G $T/gen.bpfc -f $T/20.upper >/dev/null && grep -q "match dst-port 53" $T/gen.bpfc'
check "unknown type: an error" eval '! $BPFC -i $IF -T -f $T/x.nosuchtype 2>/dev/null'
cp $T/sys/upper $T/etc/upper
sed -i 's/^echo "name upper/echo "name etc-upper/' $T/etc/upper
check "/etc/bpfc/frontends overrides /usr/libexec" eval '$BPFC -i $IF -T -G $T/gen.bpfc -f $T/20.upper >/dev/null && grep -q "name etc-upper" $T/gen.bpfc'
rm $T/etc/upper
printf 'FAIL\n' > $T/bad.upper
check "a failing frontend fails the compile" eval '! $BPFC -i $IF -T -f $T/bad.upper 2>$T/err'
check "with its message" grep -q 'told to fail' $T/err
chmod 777 $T/sys/upper
check "a world-writable frontend is refused" eval '! $BPFC -i $IF -T -f $T/20.upper 2>/dev/null'
chmod 755 $T/sys/upper
echo extra > $T/conf/extra.txt
check "-M lists the frontend and its depends" eval 'BPFC_CONF_ROOT=$T/conf $BPFC -M -f $T/20.upper | grep -q extra.txt && BPFC_CONF_ROOT=$T/conf $BPFC -M -f $T/20.upper | grep -q /upper$'

echo "== bpfcd"
cat > $T/bpfc.conf <<EOF
bpfc_path = $BPFC
config_dir = $T/conf/interfaces.d
state_dir = $T/run
EOF
status_of() {
	awk -v p="$1" '$1=="slot" { delete kv; for (n = 2; n <= NF; n++) { split($n, x, "="); kv[x[1]] = x[2] }
		if (kv["iface"] == "'$IF'" && kv["prio"] == p) print kv["status"] }' $T/run/state
}
prog_at() { tc filter show dev $IF ingress pref $1 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
eventually() { for _ in $(seq 50); do "$@" && return 0; sleep 0.1; done; return 1; }
is_status() { [ "$(status_of $1)" = "$2" ]; }
reload() { $BPFCCTL -c $T/bpfc.conf reload >/dev/null 2>&1; }
printf 'DROP-PORT 53\nfirst\n' > $T/conf/interfaces.d/$IF/ingress/10.upper
printf 'DROP-PORT 54\n' > $T/conf/interfaces.d/$IF/ingress/30.upper
BPFC_CONF_ROOT=$T/conf $BPFCD -c $T/bpfc.conf >> $T/log 2>&1 &
DPID=$!
for _ in $(seq 100); do [ -f $T/run/state ] && break; sleep 0.1; done
[ -f $T/run/state ] || { test_fail "bpfcd started"; tail $T/log; kill $DPID; DPID=; tests_exit; }
check "10.upper installed" eventually is_status 10 installed
check "meta file written" grep -q 'rule first' $T/run/meta/$IF.ingress.10
check "show --source prints the translation" eval '$BPFCCTL -c $T/bpfc.conf show $IF ingress 10 --source | grep -q "match dst-port 53"'
id10=$(prog_at 10)
printf 'DROP-PORT 53\nsecond\n' > $T/conf/interfaces.d/$IF/ingress/10.upper
reload
check "a changed file is reinstalled" eventually eval '[ -n "$(prog_at 10)" ] && [ "$(prog_at 10)" != "$id10" ]'
check "and its meta updated" grep -q 'rule second' $T/run/meta/$IF.ingress.10
id10=$(prog_at 10)
echo changed > $T/conf/extra.txt
reload
check "a changed depends file reinstalls" eventually eval '[ "$(prog_at 10)" != "$id10" ]'
id10=$(prog_at 10)
printf 'FAIL\n' > $T/conf/interfaces.d/$IF/ingress/10.upper
reload
check "failure: previous program kept (default)" eventually is_status 10 failed-kept
check "same program still attached" [ "$(prog_at 10)" = "$id10" ]
check "status counts it as a problem" eval '$BPFCCTL -c $T/bpfc.conf status >/dev/null; [ $? -eq 2 ]'
printf 'REMOVE\nDROP-PORT 54\n' > $T/conf/interfaces.d/$IF/ingress/30.upper
reload
check "30.upper with option on-failure remove" eventually is_status 30 installed
printf 'REMOVE\nFAIL\n' > $T/conf/interfaces.d/$IF/ingress/30.upper
reload
check "failure: removed (the running program said remove)" eventually is_status 30 failed
check "nothing at 30" eventually eval '[ -z "$(prog_at 30)" ]'
printf 'match udp; drop; end-match\n' > $T/conf/interfaces.d/$IF/ingress/30.bpfc
reload
check "two files for one priority: a conflict" eventually eval 'grep -q "prio=30 .*conflict" $T/run/state || $BPFCCTL -c $T/bpfc.conf status 2>&1 | grep -q "30.*conflict"'
rm $T/conf/interfaces.d/$IF/ingress/30.*
rm $T/conf/interfaces.d/$IF/ingress/10.upper
reload
check "a removed file: program removed" eventually eval '[ -z "$(prog_at 10)" ]'
check "and its meta and translation" eventually eval '[ ! -e $T/run/meta/$IF.ingress.10 ] && [ ! -e $T/run/generated/$IF.ingress.10.bpfc ]'

kill $DPID; wait $DPID 2>/dev/null; DPID=      # before tests_exit, which waits for every job
tests_exit
