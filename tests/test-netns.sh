#!/bin/bash
#
# Network namespace test for bpfcd -n, bpfcctl -n and the scripts' -n.
#
# Uses a throwaway configuration tree (BPFC_CONF_ROOT) and state tree
# (BPFC_RUN_ROOT), namespaces named bnt-* (removed afterwards) and pinned maps
# under /sys/fs/bpf/netns/bnt-*.
#
#   bash tests/test-netns.sh [-d] [-k]     -d: show daemon logs on failure, -k: keep temp dir
#
# Must be run as root from the repository root after `make`. Needs iproute2,
# unshare and nsenter.

if [ "$(id -u)" != "0" ]; then echo "Must be run as root"; exit 1; fi
DEBUG=0; KEEP=0
for a in "$@"; do [ "$a" = "-d" ] && DEBUG=1; [ "$a" = "-k" ] && KEEP=1; done

RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; NC='\e[0m'
TOP=$(cd "$(dirname "$0")/.." && pwd)
BPFC=$TOP/bpfc
BPFCD=$TOP/bpfcd/bpfcd
BPFCCTL=$TOP/bpfcd/bpfcctl
for b in "$BPFC" "$BPFCD" "$BPFCCTL"; do
	[ -x "$b" ] || { echo "$b not built; run make first"; exit 1; }
done
for t in ip unshare nsenter; do
	command -v $t >/dev/null || { echo -e "${YELLOW}SKIP${NC}: $t not found"; exit 0; }
done
grep -qs " /sys/fs/bpf bpf " /proc/self/mounts || mount -t bpf bpf /sys/fs/bpf

T=$(mktemp -d /tmp/bpfc-netns.XXXXXX)
chmod 755 "$T"
export BPFC_CONF_ROOT=$T/etc BPFC_RUN_ROOT=$T/run BPFCCTL
E=$T/etc
PASS=0; FAIL=0
PIDS=()
LOGS=()
HOST_NS=$(readlink /proc/self/ns/net)

cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
	[ -n "${POD:-}" ] && kill "$POD" 2>/dev/null
	for n in $(ip netns list 2>/dev/null | awk '/^bnt-/ {print $1}'); do ip netns del "$n"; done
	for l in bnt-h1 bnt-h2 bnt-hv bnt-hv2 bnt-eth0 bnt-lo; do ip link del $l 2>/dev/null; done
	rm -rf /sys/fs/bpf/netns/bnt-*
	rmdir /sys/fs/bpf/netns 2>/dev/null
	[ $KEEP -eq 1 ] && echo "kept $T" || rm -rf "$T"
}
trap cleanup EXIT

ok()  { echo -e "  $* ${GREEN}PASS${NC}"; PASS=$((PASS + 1)); }
bad() {
	echo -e "  $* ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
	if [ $DEBUG -eq 1 ]; then for l in "${LOGS[@]}"; do echo "---- $l"; tail -8 "$l"; done; echo "----"; fi
}
check() { local n="$1"; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }
eventually() { for _ in $(seq 60); do "$@" && return 0; sleep 0.1; done; return 1; }

# in_ns <ns-file|name> cmd... ; filters in a namespace given by name or file
in_ns() { local n=$1; shift; case $n in /*) nsenter --net="$n" "$@" ;; *) ip netns exec "$n" "$@" ;; esac; }
prog_in() { in_ns "$1" tc filter show dev "$2" "$3" pref "$4" 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
has_in() { [ -n "$(prog_in "$@")" ]; }
none_in() { [ -z "$(prog_in "$@")" ]; }
state() { cat "$T/run/netns/$1/state" 2>/dev/null; }
nsfield() { state "$1" | sed -n "s/^daemon.* $2=\([^ ]*\).*/\1/p" | sed 's/%20/ /g'; }
slot_status() {
	state "$1" | awk -v i="$2" -v d="$3" -v p="$4" '$1=="slot" {
		delete kv; for (n = 2; n <= NF; n++) { split($n, x, "="); kv[x[1]] = x[2] }
		if (kv["iface"] == i && kv["dir"] == d && kv["prio"] == p) print kv["status"] }'
}
is_slot() { [ "$(slot_status "$1" "$2" "$3" "$4")" = "$5" ]; }
waiting() { [ "$(nsfield "$1" netns_status)" = waiting ]; }
active() { [ "$(nsfield "$1" netns_status)" = active ]; }
daemon_ns() { readlink "/proc/$1/ns/net"; }
start() {   # start <netns> -> sets LAST_PID
	local log=$T/log.$1
	LOGS+=("$log")
	"$BPFCD" -n "$1" >> "$log" 2>&1 &
	LAST_PID=$!
	PIDS+=("$LAST_PID")
	eventually test -s "$T/run/netns/$1/state"
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
logged() { grep -q -- "$2" "$T/log.$1"; }
prog() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; }

mkdir -p "$E" "$T/run"
printf 'bpfc_path = %s\non_external_change = log\nreinstall_limit = 7\nmap_dir = /should/not/be/used\n' "$BPFC" > "$E/bpfc.conf"

# ------------------------------------------------------------------ config
echo "configuration"
prog "$E/netns/bnt-a/interfaces.d/eth0/ingress/10.bpfc" 'match tcp; drop'
OUT=$("$BPFCCTL" -n bnt-a env)
check "no own bpfc.conf: global file is the fallback"   eval 'grep -q "^BPFC_CONF_FALLBACK=.1.$" <<< "$OUT"'
check "...but not its paths (config/map/state defaults)" eval 'grep -q "^BPFC_CONFIG_DIR=.$E/netns/bnt-a/interfaces.d.$" <<< "$OUT" &&
	grep -q "^BPFC_MAP_DIR=./sys/fs/bpf/netns/bnt-a.$" <<< "$OUT" && grep -q "^BPFC_STATE_DIR=.$T/run/netns/bnt-a.$" <<< "$OUT"'
check "bpfcd -t shows the resolution"                  eval '"$BPFCD" -n bnt-a -t | grep -q "found: *no: /run/netns/bnt-a"'
check "invalid namespace name refused"                 eval '! "$BPFCD" -n "../x" -t >/dev/null 2>&1 && ! "$BPFCCTL" -n "-x" env >/dev/null 2>&1'
printf 'netns_path = /run/netns/x\n' >> "$E/bpfc.conf"
check "netns_path in the global file refused"          eval '! "$BPFCD" -t >/dev/null 2>&1 && ! "$BPFCD" -n bnt-a -t >/dev/null 2>&1'
sed -i '/^netns_path/d' "$E/bpfc.conf"
mkdir -p "$E/netns/bnt-z"; printf 'netns_path = /a\nnetns_veth = v0\n' > "$E/netns/bnt-z/bpfc.conf"
check "netns_path and netns_veth together refused"     eval '! "$BPFCD" -n bnt-z -t >/dev/null 2>&1'
printf 'netns_path = relative/path\n' > "$E/netns/bnt-z/bpfc.conf"
check "relative netns_path refused"                    eval '! "$BPFCD" -n bnt-z -t >/dev/null 2>&1'
rm -rf "$E/netns/bnt-z"

# ------------------------------------------------------------------ by name
echo "named namespace (/run/netns/<name>)"
ip link add bnt-eth0 type veth peer name bnt-lo      # same name on the host: must stay untouched
mkdir -p "$E/netns/bnt-a/interfaces.d/bnt-eth0/ingress"
prog "$E/netns/bnt-a/interfaces.d/bnt-eth0/ingress/10.bpfc" 'match tcp; drop'
prog "$E/netns/bnt-a/interfaces.d/eth0/ingress/20.bpfc" 'match udp; set map NTMAP 1 1'
start bnt-a; PA=$LAST_PID
check "starts before the namespace exists, waits"      eventually waiting bnt-a
check "...and installs nothing on the host"            eval 'sleep 0.5; [ -z "$(tc filter show dev bnt-eth0 ingress)" ]'
ip netns add bnt-a
ip link add bnt-h1 type veth peer name eth0 netns bnt-a
ip -n bnt-a link add bnt-eth0 type veth peer name bnt-x
check "namespace found: programs installed in it"      eventually eval 'has_in bnt-a eth0 ingress 10 && has_in bnt-a bnt-eth0 ingress 10'
check "host interface of the same name untouched"      eval '[ -z "$(tc filter show dev bnt-eth0 ingress)" ]'
check "global behavior settings used (fallback)"       eval '"$BPFCCTL" -n bnt-a | grep -q "external changes: log"'
check "map pinned in the namespace's map dir"          eventually eval 'has_in bnt-a eth0 ingress 20 && test -e /sys/fs/bpf/netns/bnt-a/NTMAP'
check "new interface in the namespace gets programs"   eval 'ip -n bnt-a link add bnt-new type veth peer name bnt-new2; mkdir -p $E/netns/bnt-a/interfaces.d/bnt-new/egress;
	printf "drop\n" > $E/netns/bnt-a/interfaces.d/bnt-new/egress/5.bpfc; "$BPFCCTL" -n bnt-a reload >/dev/null; has_in bnt-a bnt-new egress 5'
ID10=$(prog_in bnt-a eth0 ingress 10)
ip netns del bnt-a
check "namespace deleted: waits"                       eventually waiting bnt-a
check "...and lets go of it (back in the host's)"      eventually eval '[ "$(daemon_ns $PA)" = "$HOST_NS" ]'
ip netns add bnt-a
ip link del bnt-h1 2>/dev/null
ip link add bnt-h1 type veth peer name eth0 netns bnt-a
check "re-created namespace: programs installed again" eventually eval 'has_in bnt-a eth0 ingress 10 && active bnt-a'
check "SIGHUP while waiting looks at once"             eval 'stop $PA; ip netns del bnt-a; start bnt-a; PA=$LAST_PID; eventually waiting bnt-a &&
	ip netns add bnt-a && ip link del bnt-h1 2>/dev/null; ip link add bnt-h1 type veth peer name eth0 netns bnt-a;
	kill -HUP $PA; for _ in 1 2 3 4 5 6 7; do has_in bnt-a eth0 ingress 10 && break; sleep 0.1; done; has_in bnt-a eth0 ingress 10'

echo "restart"
ID10=$(prog_in bnt-a eth0 ingress 10)
stop $PA
check "programs stay after stop"                       eval '[ "$(prog_in bnt-a eth0 ingress 10)" = "$ID10" ]'
start bnt-a; PA=$LAST_PID
check "restart in the same namespace adopts"           eventually eval 'logged bnt-a "adopted" && [ "$(prog_in bnt-a eth0 ingress 10)" = "$ID10" ]'
stop $PA
ip netns del bnt-a; ip netns add bnt-a; ip link del bnt-h1 2>/dev/null; ip link add bnt-h1 type veth peer name eth0 netns bnt-a
start bnt-a; PA=$LAST_PID
check "restart in a different namespace installs afresh" eventually eval 'logged bnt-a "different namespace" && has_in bnt-a eth0 ingress 10'

# ------------------------------------------------------------------ bpfcctl
echo "bpfcctl"
check "status -n exits 0 and names the namespace"      eval '"$BPFCCTL" -n bnt-a --color=never > $T/st; [ $? -eq 0 ] && grep -q "^netns: bnt-a" $T/st'
check "kernel cross-checked inside the namespace"      eval 'grep -E "^eth0 +ingress +10 " $T/st | grep -q " ok "'
ip -n bnt-a link add bnt-only type veth peer name bnt-only2
check "exec runs inside, /sys remounted for it"        eval '"$BPFCCTL" -n bnt-a exec ls /sys/class/net | grep -qx bnt-only && ! ls /sys/class/net | grep -qx bnt-only'
check "exec keeps bpffs reachable"                     eval '"$BPFCCTL" -n bnt-a exec sh -c "test -e \$BPFC_MAP_DIR/NTMAP && test \"\$BPFC_IN_NETNS\" = bnt-a"'
check "exec passes the command's options through"      eval '"$BPFCCTL" -n bnt-a exec ip -o link show eth0 | grep -q eth0'
check "reload --no-wait"                               eval '"$BPFCCTL" -n bnt-a reload --no-wait | grep -q "Sent SIGHUP"'
check "exec without -n refused"                        eval '! "$BPFCCTL" exec true 2>/dev/null'
if id nobody >/dev/null 2>&1; then
	chmod -R a+rX "$T"
	install -m 0755 "$BPFCCTL" "$T/bpfcctl"
	check "non-root: daemon running, kernel shown as ?" eval 'su -s /bin/sh nobody -c "BPFC_CONF_ROOT=$E BPFC_RUN_ROOT=$T/run $T/bpfcctl -n bnt-a --color=never" > $T/nr 2>&1;
		[ $? -eq 0 ] && grep -q "running" $T/nr && grep -E "^eth0 +ingress +10 " $T/nr | grep -q " ? "'
fi

# ------------------------------------------------------------------ symlinks
echo "netns_path through symlinks"
ip netns add bnt-b1; ip netns add bnt-b2
ip -n bnt-b1 link add eth0 type veth peer name p; ip -n bnt-b2 link add eth0 type veth peer name p
mkdir -p "$T/links" "$E/netns/bnt-b"
ln -s "$T/links/current" "$T/links/web"
ln -s /run/netns/bnt-b1 "$T/links/current"
printf 'bpfc_path = %s\nnetns_path = %s/links/web\n' "$BPFC" "$T" > "$E/netns/bnt-b/bpfc.conf"
prog "$E/netns/bnt-b/interfaces.d/eth0/ingress/10.bpfc" 'match tcp; drop'
start bnt-b; PB=$LAST_PID
check "own bpfc.conf used (not the fallback)"          eval '"$BPFCCTL" -n bnt-b env | grep -q "^BPFC_CONF_FALLBACK=..$"'
check "chain followed to the namespace"                eventually has_in bnt-b1 eth0 ingress 10
check "status shows the chain"                         eval '"$BPFCCTL" -n bnt-b | grep -q "links/web -> .*links/current -> /run/netns/bnt-b1"'
ln -s /run/netns/bnt-b2 "$T/links/new"; mv -T "$T/links/new" "$T/links/current"
check "link retargeted: programs move"                 eventually eval 'has_in bnt-b2 eth0 ingress 10 && none_in bnt-b1 eth0 ingress 10'
ip netns del bnt-b2
check "dangling link: waits"                           eventually waiting bnt-b
ln -sfn /run/netns/bnt-b1 "$T/links/current"
check "pointed back: installed again"                  eventually has_in bnt-b1 eth0 ingress 10
unshare --net sleep 300 & POD=$!; sleep 0.3
nsenter -t $POD -n ip link add eth0 type veth peer name p
printf 'bpfc_path = %s\nnetns_path = /proc/%d/ns/net\n' "$BPFC" "$POD" > "$E/netns/bnt-b/bpfc.conf"
kill -HUP $PB
check "netns_path changed on reload: followed"         eventually eval 'has_in /proc/$POD/ns/net eth0 ingress 10 && none_in bnt-b1 eth0 ingress 10'
kill $POD; wait $POD 2>/dev/null; POD=
check "process exits: /proc path gone, waits"          eventually waiting bnt-b

# ------------------------------------------------------------------ veth
echo "netns_veth"
mkdir -p "$E/netns/bnt-v"
printf 'bpfc_path = %s\nnetns_veth = bnt-hv\n' "$BPFC" > "$E/netns/bnt-v/bpfc.conf"
prog "$E/netns/bnt-v/interfaces.d/eth0/ingress/10.bpfc" 'match tcp; drop'
start bnt-v; PV=$LAST_PID
check "no such veth: waits"                            eventually eval 'waiting bnt-v && nsfield bnt-v netns_target | grep -q "no such interface"'
ip link add bnt-hv type veth peer name eth0tmp
check "peer not moved yet: waits"                      eventually eval 'nsfield bnt-v netns_target | grep -q "still in this namespace"'
unshare --net sleep 300 & POD=$!; sleep 0.3
ip link set eth0tmp netns $POD; nsenter -t $POD -n ip link set eth0tmp name eth0
check "peer in a process-only namespace: found"        eventually eval 'has_in /proc/$POD/ns/net eth0 ingress 10'
check "...through the process"                         eval 'nsfield bnt-v netns_target | grep -q "/proc/$POD/ns/net"'
kill $POD; wait $POD 2>/dev/null; POD=
check "process gone: bpfcd lets go"                    eventually eval 'waiting bnt-v && [ "$(daemon_ns $PV)" = "$HOST_NS" ]'
check "...so the namespace and veth are freed"         eventually eval '! ip link show bnt-hv >/dev/null 2>&1'
ip netns add bnt-v1; ip netns add bnt-v2
ip link add bnt-hv type veth peer name eth0 netns bnt-v1
check "peer in a named namespace: found"               eventually has_in bnt-v1 eth0 ingress 10
ip link del bnt-hv
ip link add bnt-hv type veth peer name eth0 netns bnt-v2
check "veth re-created into another namespace: moves"  eventually eval 'has_in bnt-v2 eth0 ingress 10 && active bnt-v'
check "not a veth: refused with a reason"              eval 'ip link del bnt-hv; ip link add bnt-hv type bridge 2>/dev/null || ip tuntap add bnt-hv mode tun; eventually eval "nsfield bnt-v netns_target | grep -q \"not a veth\""'

# ------------------------------------------------------------------ several
echo "several instances"
check "all-netns lists every instance"                 eval '"$BPFCCTL" --all-netns --color=never > $T/all; grep -q "==== bnt-a ====" $T/all && grep -q "==== bnt-b ====" $T/all && grep -q "==== bnt-v ====" $T/all'
check "...exit status is the worst (some waiting=ok)"  eval '"$BPFCCTL" --all-netns >/dev/null; [ $? -le 2 ]'
mkdir -p "$E/netns/bnt-c/interfaces.d/eth0/ingress"
prog "$E/netns/bnt-c/interfaces.d/eth0/ingress/20.bpfc" 'match udp; set map NTMAP 1 1'
ip netns add bnt-c; ip link add bnt-h2 type veth peer name eth0 netns bnt-c
start bnt-c; PC=$LAST_PID
check "same map name in two namespaces: kept apart"    eventually eval 'test -e /sys/fs/bpf/netns/bnt-c/NTMAP && test -e /sys/fs/bpf/netns/bnt-a/NTMAP &&
	[ "$(stat -c %i /sys/fs/bpf/netns/bnt-c/NTMAP)" != "$(stat -c %i /sys/fs/bpf/netns/bnt-a/NTMAP)" ]'
printf 'bpfc_path = %s\nremove_on_stop = yes\n' "$BPFC" > "$E/netns/bnt-c/bpfc.conf"
kill -HUP $PC; sleep 0.5
stop $PC
check "remove_on_stop inside a namespace"              eval 'none_in bnt-c eth0 ingress 20'

# ------------------------------------------------------------------ scripts
echo "scripts"
check "bpfc-dataplane-status -n uses its config_dir"   eval 'BPFC=$BPFC $TOP/dataplane/bpfc-dataplane-status -n bnt-a 2>&1 | grep -q "$E/netns/bnt-a/interfaces.d"'
check "bpfc-ecmp-status -n uses its map_dir"           eval 'BPFC=$BPFC $TOP/ecmp/bpfc-ecmp-status -n bnt-a 2>&1 | grep -q "/sys/fs/bpf/netns/bnt-a"'
check "bpfc-flows -n runs inside it"                   eval 'BPFC_BIN=$BPFC $TOP/flowmon/bpfc-flows -n bnt-a --json >/dev/null 2>&1 && test -e $T/run/netns/bnt-a/bpfc-flows.prev.json'
ip -n bnt-a tuntap add bnt-tun mode tun 2>/dev/null; ip -n bnt-a link add m1 type veth peer name m1p; ip -n bnt-a link add m2 type veth peer name m2p
if ip -n bnt-a link show bnt-tun >/dev/null 2>&1; then
	check "bpfc-ecmp-gen -n sees the namespace's devices" eval '$TOP/ecmp/bpfc-ecmp-gen -n bnt-a -M m1=10M -M m2=10M -I bnt-tun -o - 2>&1 | grep -q "only Ethernet interfaces"'
fi
check "bpfc-dataplane-gen -n defaults to its dirs"     eval '$TOP/dataplane/bpfc-dataplane-gen -n bnt-a -i eth0 --remove-maps | grep -q "/sys/fs/bpf/netns/bnt-a"'

echo
echo -e "netns tests: ${GREEN}$PASS passed${NC}, $([ $FAIL -eq 0 ] && echo 0 || echo -e "${RED}$FAIL failed${NC}")"
[ $FAIL -eq 0 ]
