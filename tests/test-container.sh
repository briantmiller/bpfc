#!/bin/bash
#
# Container test for bpfcd-entrypoint: runs bpfcd as PID 1 in a new PID and
# mount namespace, chrooted into a root filesystem that has no systemd (and,
# for a static build, no libc): only busybox plus `make install`. This is
# what `podman run --network host` does, minus the image format.
#
#   bash tests/test-container.sh [-d] [-k]    -d: show logs on failure, -k: keep temp dir
#   RPMS="bpfc-*.rpm bpfc-container-*.rpm" bash tests/test-container.sh
#                                             build the image from packages instead
#
# Needs root, a static busybox (busybox-static, or BUSYBOX=/path), unshare,
# nsenter and setpriv (util-linux). Run from the repository root after `make`.

if [ "$(id -u)" != "0" ]; then echo "Must be run as root"; exit 1; fi
DEBUG=0; KEEP=0
for a in "$@"; do [ "$a" = "-d" ] && DEBUG=1; [ "$a" = "-k" ] && KEEP=1; done

RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; NC='\e[0m'
TOP=$(cd "$(dirname "$0")/.." && pwd)
BUSYBOX=${BUSYBOX:-$(command -v busybox)}
for t in unshare nsenter setpriv; do
	command -v $t >/dev/null || { echo -e "${YELLOW}SKIP${NC}: $t not found"; exit 0; }
done
if [ -z "$BUSYBOX" ] || ! file -L "$BUSYBOX" | grep -q "statically linked"; then
	echo -e "${YELLOW}SKIP${NC}: needs a statically linked busybox (install busybox-static or set BUSYBOX=)"
	exit 0
fi
if [ -z "${RPMS:-}" ]; then
	for b in bpfc bpfcd/bpfcd bpfcd/bpfcctl; do
		[ -x "$TOP/$b" ] || { echo "$TOP/$b not built; run make first"; exit 1; }
	done
fi

T=$(mktemp -d /tmp/bpfc-ctr.XXXXXX)
R=$T/root
A=ctrA
PASS=0; FAIL=0; UPID=
cleanup() {
	stop_ctr 2>/dev/null
	ip link del $A 2>/dev/null
	[ $KEEP -eq 1 ] && echo "kept $T" || rm -rf "$T"
}
trap cleanup EXIT

ok()  { echo -e "  $* ${GREEN}PASS${NC}"; PASS=$((PASS + 1)); }
bad() {
	echo -e "  $* ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
	if [ $DEBUG -eq 1 ]; then echo "---- container log (tail)"; tail -15 "$T/log"; echo "----"; fi
}
check() { local n="$1"; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }
eventually() { for _ in $(seq 50); do "$@" && return 0; sleep 0.1; done; return 1; }
prog_at() { tc filter show dev "$1" "$2" pref "$3" 2>/dev/null | sed -n 's/.* id \([0-9]*\) .*/\1/p' | head -1; }
has_prog() { [ -n "$(prog_at "$@")" ]; }
no_prog()  { [ -z "$(prog_at "$@")" ]; }
logged()   { grep -q -- "$1" "$T/log"; }

# ---- the image: busybox + the build (or the RPMs), nothing else ------------
mkdir -p "$R/bin" "$R/proc" "$R/sys" "$R/dev" "$R/tmp" "$R/run"
cp "$BUSYBOX" "$R/bin/busybox"
chroot "$R" /bin/busybox --install -s /bin
mknod -m 666 "$R/dev/null" c 1 3
if [ -n "${RPMS:-}" ]; then
	# --nodeps only because this rpmdb does not know busybox provides /bin/sh.
	# shellcheck disable=SC2086
	rpm --root "$R" --initdb && rpm --root "$R" -i --nodeps $RPMS || { echo "rpm install failed"; exit 1; }
else
	make -s -C "$TOP" install DESTDIR="$R" >/dev/null || { echo "make install failed"; exit 1; }
fi
if ! file "$R/usr/sbin/bpfcd" | grep -q "statically linked"; then
	# Dynamic build: copy in just the shared libraries the binaries need.
	for lib in $(ldd "$R/usr/sbin/bpfc" "$R/usr/sbin/bpfcd" "$R/usr/sbin/bpfcctl" | grep -o '/[^ ]*\.so[^ ]*' | sort -u); do
		mkdir -p "$R$(dirname "$lib")"; cp -L "$lib" "$R$lib"
	done
	LIBC_NOTE="dynamic build, shared libraries copied in"
else
	LIBC_NOTE="static build, no libc in the image"
fi
if [ -n "${RPMS:-}" ]; then
	LIBC_NOTE="$LIBC_NOTE; installed from $(rpm --root "$R" -qa | sort | tr '\n' ' ')"
fi
mkdir -p "$R/etc/bpfc/interfaces.d/$A/ingress" "$R/etc/bpfc/interfaces.d/$A/egress"
printf 'match tcp; drop\n'                    > "$R/etc/bpfc/interfaces.d/$A/ingress/10.bpfc"
printf 'match udp; set map CTRMAP 1 1\n'      > "$R/etc/bpfc/interfaces.d/$A/ingress/20.bpfc"
printf 'match icmp; drop\n'                   > "$R/etc/bpfc/interfaces.d/$A/egress/10.bpfc"
ip link add $A type veth peer name ${A}p

# ---- the "container runtime" -----------------------------------------------
# start_ctr [bpffs|nobpffs] [setpriv args...] -- [entrypoint args...]
# New PID + mount namespace, host network, /sys from the host, optionally a
# bpffs at /sys/fs/bpf (the -v /sys/fs/bpf:/sys/fs/bpf case), then chroot.
start_ctr() {
	local fs=$1; shift
	local priv=()
	while [ $# -gt 0 ] && [ "$1" != "--" ]; do priv+=("$1"); shift; done
	[ "${1:-}" = "--" ] && shift
	: > "$T/log"
	unshare --pid --fork --mount --propagation private sh -c '
		R=$1; fs=$2; shift 2
		mount -t proc proc "$R/proc"
		mount --rbind /sys "$R/sys"
		if [ "$fs" = bpffs ]; then mount -t bpf bpf "$R/sys/fs/bpf"; else umount "$R/sys/fs/bpf" 2>/dev/null; true; fi
		exec "$@"' sh "$R" "$fs" \
		${priv[@]+"${priv[@]}"} chroot "$R" /usr/sbin/bpfcd-entrypoint "$@" >> "$T/log" 2>&1 &
	UPID=$!
	BPID=
	for _ in $(seq 50); do BPID=$(pgrep -P "$UPID" | head -1); [ -n "$BPID" ] && break; sleep 0.1; done
}
ctr_pid1() { [ -n "$BPID" ] && [ "$(cat /proc/$BPID/comm 2>/dev/null)" = bpfcd ]; }
# podman exec: same PID and mount namespace and root directory as PID 1.
ctr_exec() { nsenter -t "$BPID" -p -m -r -w /bin/sh -c "$*"; }
stop_ctr() {
	[ -n "$UPID" ] || return 0
	kill -TERM "$BPID" 2>/dev/null
	for _ in $(seq 50); do kill -0 "$UPID" 2>/dev/null || break; sleep 0.1; done
	kill -KILL "$UPID" 2>/dev/null
	wait "$UPID" 2>/dev/null
	CTR_RC=$?
	UPID=
}
ready() { logged "program(s) installed"; }

echo "image: $LIBC_NOTE"

echo "start as PID 1"
start_ctr bpffs --
check "bpfcd is PID 1 of the container"           eventually ctr_pid1
check "daemon reports it runs as PID 1"           eventually logged "starting as PID 1"
check "entrypoint found the bpffs mount"          logged "pinned maps go to /sys/fs/bpf"
check "programs installed on the host interface"  eventually eval 'ready && has_prog $A ingress 10 && has_prog $A egress 10'
check "map-using program installed and pinned"    eval 'has_prog $A ingress 20 && ctr_exec "test -e /sys/fs/bpf/CTRMAP"'
check "bpfcctl via exec sees the daemon running"  eval 'ctr_exec "bpfcctl status" >/dev/null; [ $? -eq 0 ]'

echo "signals and reload"
ID10=$(prog_at $A ingress 10)
printf 'match tcp; match tcp-dst 22; drop\n' > "$R/etc/bpfc/interfaces.d/$A/ingress/10.bpfc"
kill -HUP "$BPID"                                  # podman kill --signal HUP
check "SIGHUP from the host reloads"              eventually eval '[ "$(prog_at $A ingress 10)" != "$ID10" ] && has_prog $A ingress 10'
rm "$R/etc/bpfc/interfaces.d/$A/egress/10.bpfc"
check "bpfcctl reload via exec"                   eval 'ctr_exec "bpfcctl reload" | grep -q "Reloaded: 2 installed"'
check "deleted file detached"                     no_prog $A egress 10
ctr_exec "sleep 0.2 & exit 0"                      # leaves an orphan that is re-parented to PID 1
sleep 0.6
check "orphaned process reaped (no zombies)"      eval '! ps -o stat= --ppid $BPID | grep -q Z'

echo "stop"
stop_ctr
check "SIGTERM stops PID 1 cleanly (exit 0)"      eval '[ "$CTR_RC" = 0 ] && logged "received Terminated, stopping"'
check "programs stay attached after stop"         has_prog $A ingress 10

echo "restart"
start_ctr bpffs --
check "restart adopts attached programs"          eventually logged "adopted 2 program(s)"
stop_ctr

echo "environment overrides"
BPFCD_ON_EXTERNAL_CHANGE=log BPFCD_REMOVE_ON_STOP=yes start_ctr bpffs --
eventually ready >/dev/null
check "BPFCD_ON_EXTERNAL_CHANGE=log applied"      logged "external changes: log"
tc filter del dev $A ingress pref 10
check "external removal logged, not reinstalled"  eventually eval 'grep -q "status=removed-externally" $R/run/bpfc/state'
check "bpfcctl via exec reports it (exit 2)"      eval 'ctr_exec "bpfcctl status" >/dev/null; [ $? -eq 2 ]'
stop_ctr
check "BPFCD_REMOVE_ON_STOP=yes detaches on stop" no_prog $A ingress 20
check "invalid override refused"                  eval 'BPFCD_REINSTALL_LIMIT=lots start_ctr bpffs --; stop_ctr; logged "invalid value .lots. for BPFCD_REINSTALL_LIMIT"'

echo "without a host bpffs"
start_ctr nobpffs --
check "entrypoint mounts a private bpffs, warns"  eventually logged "mounted a private bpffs"
check "map-using program still installs"         eventually has_prog $A ingress 20
stop_ctr

echo "privilege checks"
start_ctr bpffs setpriv --bounding-set=-net_admin --inh-caps=-net_admin --
sleep 1
check "missing CAP_NET_ADMIN refused, named"      eval 'logged "missing CAP_NET_ADMIN" && ! ctr_pid1'
stop_ctr
start_ctr bpffs setpriv --bounding-set=-sys_admin,-bpf --inh-caps=-sys_admin,-bpf --
sleep 1
check "missing CAP_BPF and CAP_SYS_ADMIN refused" eval 'logged "missing CAP_BPF" && ! ctr_pid1'
stop_ctr

echo "other commands"
check "--background is refused"                   eval 'start_ctr bpffs -- --background; stop_ctr; logged "must stay in the foreground"'
check "other commands run instead of bpfcd"       eval 'start_ctr bpffs -- bpfcctl --version; stop_ctr; logged "^bpfcctl "'

echo
echo -e "container tests: ${GREEN}$PASS passed${NC}, $([ $FAIL -eq 0 ] && echo 0 || echo -e "${RED}$FAIL failed${NC}")"
[ $FAIL -eq 0 ]
