#!/bin/bash
#
# test-verifier-budget.sh - how much of the kernel verifier's budget the
# generated dataplane programs use.
#
# The verifier gives up after processing 1,000,000 instructions (it follows
# every path, so a program's cost is far larger than its length). The
# dataplane's largest program is close to that, and a change to bpfc or the
# generator can push it over: the program then fails to load on someone's
# system. Every program of every profile, and of the extremes of the
# structural settings, is loaded here and its "verified" count (kernel 5.16+,
# from bpfc -I) must stay below BUDGET_PCT percent of the limit.
#
#   BUDGET_PCT   fail above this share of 1,000,000 (default 85)
#   VB_REPORT    write "profile dir prio verified insns" lines to this file
#
# Needs root (loading programs). Kernels without verified_insns: SKIP.

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root "verifier-budget"

BPFC=$PWD/bpfc
GEN=$PWD/dataplane/bpfc-dataplane-gen
LIMIT=1000000
BUDGET_PCT=${BUDGET_PCT:-85}
NS=bpfcvb
T=$(mktemp -d)
MAPS=$T/maps
cleanup() {
	umount "$MAPS" 2>/dev/null
	ip netns del $NS 2>/dev/null
	rm -rf "$T"
}
trap cleanup EXIT

ulimit -l unlimited 2>/dev/null
ip netns del $NS 2>/dev/null
ip netns add $NS
ip -n $NS link add vb0 type veth peer name vb1
ip -n $NS link set vb0 up
ip -n $NS link set vb1 up
mkdir -p "$MAPS"
mount -t bpf bpffs "$MAPS" || { echo "verifier-budget (cannot mount bpffs) SKIP"; exit 0; }

# name|generator arguments
CASES="direct|--profile direct
geo|--profile geo
wan|--profile wan
geo-largest|--profile geo --arq-depth 16384 --dup-window 16384 --fec-slots 64
direct-smallest|--profile direct --arq-depth 1 --dup-window 1024 --fec-slots 16"

worst=0 worst_name=
while IFS='|' read -r name args; do
	out=$T/$name
	# shellcheck disable=SC2086
	if ! $GEN -i vb0 -o "$out" $args >/dev/null 2>"$T/gen.err"; then
		test_fail "VB-$name generate"; sed 's/^/    /' "$T/gen.err"; continue
	fi
	ip netns exec $NS "$BPFC" -i vb0 -c >/dev/null 2>&1
	for f in "$out"/vb0/egress/*.bpfc "$out"/vb0/ingress/*.bpfc; do
		dir=$(basename "$(dirname "$f")"); prio=$(basename "$f" .bpfc)
		id="VB-$name-$dir-$prio"
		if ! info=$(ip netns exec $NS "$BPFC" -m "$MAPS" -i vb0 -d "$dir" -p "$prio" -I -f "$f" 2>&1); then
			test_fail "$id load"; echo "$info" | tail -5 | sed 's/^/    /'; continue
		fi
		v=$(echo "$info" | sed -n 's/^BPFC_INFO .* verified=\([0-9]*\).*/\1/p')
		insns=$(echo "$info" | sed -n 's/^BPFC_INFO .* insns=\([0-9]*\).*/\1/p')
		if [ -z "$v" ]; then
			test_skip "$id (kernel does not report verified instructions)"; continue
		fi
		[ -n "$VB_REPORT" ] && echo "$name $dir $prio $v $insns" >> "$VB_REPORT"
		pct=$((v * 100 / LIMIT))
		[ "$v" -gt "$worst" ] && { worst=$v; worst_name="$name $dir/$prio"; }
		check "$id: $v of $LIMIT verified ($pct %), $insns insns" [ "$v" -le $((LIMIT * BUDGET_PCT / 100)) ]
	done
	$GEN -i vb0 -m "$MAPS" --remove-maps >/dev/null 2>&1
done <<< "$CASES"

[ "$worst" -gt 0 ] && echo "largest: $worst_name, $worst verified ($((worst * 100 / LIMIT)) % of the limit, budget $BUDGET_PCT %)"
tests_exit
