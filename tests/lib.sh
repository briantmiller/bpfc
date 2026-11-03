# Shared by the shell test suites; source it from the repository root.
#
# Result lines end in PASS, FAIL or SKIP, which tests/run-tests.sh counts.
# Failures are also recorded in a file, so checks run in the background (&)
# count too, and tests_exit gives the suite a matching exit status.

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

TESTS_FAILED_FILE=$(mktemp /tmp/bpfc-test-failed.XXXXXX)
trap 'rm -f "$TESTS_FAILED_FILE"' EXIT

test_pass() { echo -e "$* ${GREEN}PASS${NC}"; }
test_fail() { echo -e "$* ${RED}FAIL${NC}"; echo "$*" >> "$TESTS_FAILED_FILE"; }
test_skip() { echo -e "$* ${YELLOW}SKIP${NC}"; }

# check <name> <command ...>: PASS if the command succeeds, else FAIL.
check() { local name=$1; shift; if "$@"; then test_pass "$name"; else test_fail "$name"; fi; }

# Ends the suite after its background checks: exit 1 if any check failed.
tests_exit() {
	wait 2>/dev/null
	local n
	n=$(wc -l < "$TESTS_FAILED_FILE")
	rm -f "$TESTS_FAILED_FILE"
	[ "$n" -eq 0 ] && exit 0
	exit 1
}

# Skips the whole suite (one SKIP line, exit 0) when not run as root.
require_root() {
	[ "$(id -u)" -eq 0 ] && return 0
	test_skip "$1 (needs root)"
	rm -f "$TESTS_FAILED_FILE"
	exit 0
}

# require_cmds <suite> <command ...>: skips the whole suite unless all are installed.
require_cmds() {
	local suite=$1 missing= c
	shift
	for c; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
	[ -z "$missing" ] && return 0
	test_skip "$suite (not installed:$missing)"
	rm -f "$TESTS_FAILED_FILE"
	exit 0
}

# have_ipv6: the kernel supports IPv6 (an address can be added in a scratch namespace).
have_ipv6() {
	local ns=bpfc-probe-$$ ok=1
	ip netns add $ns 2>/dev/null || return 1
	ip -n $ns link set lo up 2>/dev/null
	ip -n $ns -6 addr add fd00::1/128 dev lo 2>/dev/null && ok=0
	ip netns del $ns 2>/dev/null
	return $ok
}

# ping_loss <ns> <procs> <count> <ping args...>: runs <procs> pings of <count>
# packets at once in namespace <ns>; prints the loss over all of them in
# hundredths of a percent (37 = 0.37 %). A ping that never reports (killed by
# its time limit) counts as all lost.
ping_loss() {
	local ns=$1 n=$2 count=$3 d i tx=0 rx=0 t r
	local -a pids=()
	shift 3
	d=$(mktemp -d)
	for i in $(seq 1 "$n"); do
		timeout 60 ip netns exec "$ns" ping -c "$count" "$@" > "$d/$i" 2>&1 &
		pids+=($!)
	done
	wait "${pids[@]}" 2>/dev/null
	for i in $(seq 1 "$n"); do
		read -r t r < <(sed -n 's/^\([0-9]*\) packets transmitted, \([0-9]*\) \(packets \)\{0,1\}received.*/\1 \2/p' "$d/$i")
		[ -n "$t" ] || { t=$count; r=0; }
		tx=$((tx + t)); rx=$((rx + r))
	done
	rm -rf "$d"
	[ "$tx" -gt 0 ] || { echo 10000; return; }
	echo $(( (tx - rx) * 10000 / tx ))
}

# pct <hundredths>: 37 -> 0.37
pct() { printf '%d.%02d' $(($1 / 100)) $(($1 % 100)); }

# require_kernel_mpls <suite>: skips the whole suite unless the kernel can
# route MPLS labels (the mpls_router module).
require_kernel_mpls() {
	[ -d /proc/sys/net/mpls ] || modprobe mpls_router 2>/dev/null
	[ -d /proc/sys/net/mpls ] && return 0
	test_skip "$1 (kernel MPLS routing not available: mpls_router)"
	rm -f "$TESTS_FAILED_FILE"
	exit 0
}
