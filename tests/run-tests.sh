#!/bin/bash
#
# Runs the test suites and totals their results.
#
#   tests/run-tests.sh [-f] [-v] [-l DIR] [-t SECS] [suite ...]
#
#   suite   compile, preprocessor, stack, bpfc, util, loops, nat, mpls, mpls-xdp, frag,
#           mpls-frag, throttle, cve-2026-98432, bpfcd, container, install,
#           verifier-budget, xdp, xdp-examples, tc-examples, ecmp, dataplane, dataplane-udp or pytest
#           (default: all of them, in that order)
#   -f      print failures only (plus the summary)
#   -v      print each suite's full output, not just its results
#   -l DIR  keep the logs in DIR (default: a new directory under /tmp)
#   -t SECS time limit per suite (default 1800)
#
# A result is any output line ending in PASS, FAIL or SKIP; pytest results
# are converted. A suite that exits non-zero without printing a FAIL counts
# as one failure, so a crash is never mistaken for success. Each suite runs
# in its own process group, which is killed afterwards, so helpers it left
# running (nc, iperf3, tcpdump) cannot hang the runner.
# Exit status: 0 when nothing failed, 1 otherwise.

cd "$(dirname "$0")/.." || exit 1

ALL="compile preprocessor stack bpfc util loops nat mpls mpls-xdp frag mpls-frag throttle cve-2026-98432 bpfcd netns container install verifier-budget xdp xdp-examples tc-examples ecmp dataplane dataplane-udp pytest"
FAILURES_ONLY=0
VERBOSE=0
LOGDIR=
TIMEOUT=1800

usage() { sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts "fvl:t:h" o; do
	case $o in
	f) FAILURES_ONLY=1 ;;
	v) VERBOSE=1 ;;
	l) LOGDIR=$OPTARG ;;
	t) TIMEOUT=$OPTARG ;;
	h) usage 0 ;;
	*) usage 2 ;;
	esac
done
shift $((OPTIND - 1))
SUITES=${*:-$ALL}

if [ -t 1 ]; then RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; BOLD='\e[1m'; NC='\e[0m'
else RED=; GREEN=; YELLOW=; BOLD=; NC=; fi

[ -n "$LOGDIR" ] || LOGDIR=$(mktemp -d /tmp/bpfc-tests.XXXXXX)
mkdir -p "$LOGDIR" || exit 1

# The command line for a suite name.
suite_cmd() {
	case $1 in
	pytest) echo "env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -v -p no:cacheprovider tests/test_bpfc.py" ;;
	mpls-xdp) echo "bash tests/test-mpls.sh -x" ;;
	*)      [ -f "tests/test-$1.sh" ] && echo "bash tests/test-$1.sh" ;;
	esac
}

# Result lines of a log, colours removed. pytest's "path::name PASSED" lines
# become "name PASS" (ERROR, at setup, counts as FAIL).
results() {
	sed 's/\x1b\[[0-9;]*m//g' "$1" | awk '
		/::[A-Za-z0-9_]+ (PASSED|FAILED|ERROR|SKIPPED)/ {
			split($1, p, "::"); r = $2
			r = (r == "PASSED") ? "PASS" : (r == "SKIPPED") ? "SKIP" : "FAIL"
			print p[2] " " r; next }
		/[ \t](PASS|FAIL|SKIP)[ \t]*$/ { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); print }'
}

# Shows a result line as it appears, coloured, honouring -f.
show() {
	local line=$1 suite=$2
	case $line in
	*FAIL) echo -e "${RED}[$suite]${NC} ${line% FAIL} ${RED}FAIL${NC}" ;;
	*SKIP) [ $FAILURES_ONLY -eq 1 ] || echo -e "[$suite] ${line% SKIP} ${YELLOW}SKIP${NC}" ;;
	*PASS) [ $FAILURES_ONLY -eq 1 ] || echo -e "[$suite] ${line% PASS} ${GREEN}PASS${NC}" ;;
	esac
}

TOTAL_P=0; TOTAL_F=0; TOTAL_S=0
SUMMARY=()

for s in $SUITES; do
	cmd=$(suite_cmd "$s")
	if [ -z "$cmd" ]; then
		echo -e "${RED}unknown suite '$s'${NC} (suites: $ALL)" >&2
		TOTAL_F=$((TOTAL_F + 1)); SUMMARY+=("$s|0|1|0|unknown suite"); continue
	fi
	log=$LOGDIR/$s.log
	[ $FAILURES_ONLY -eq 1 ] || echo -e "${BOLD}== $s${NC}"
	start=$(date +%s)

	# Own process group; output to a file, not a pipe, so leftovers cannot
	# keep the runner waiting.
	setsid bash -c "exec timeout $TIMEOUT $cmd" > "$log" 2>&1 < /dev/null &
	pid=$!
	# Stream results (or everything, with -v) while it runs.
	if [ $VERBOSE -eq 1 ] && [ $FAILURES_ONLY -eq 0 ]; then
		tail -n +1 -f --pid=$pid "$log"
	else
		seen=0
		while kill -0 $pid 2>/dev/null; do
			sleep 1
			mapfile -t lines < <(results "$log")
			for ((i = seen; i < ${#lines[@]}; i++)); do show "${lines[i]}" "$s"; done
			seen=${#lines[@]}
		done
	fi
	wait $pid; rc=$?
	kill -- -$pid 2>/dev/null       # helpers the suite left behind
	elapsed=$(( $(date +%s) - start ))

	mapfile -t lines < <(results "$log")
	if [ $VERBOSE -eq 0 ] || [ $FAILURES_ONLY -eq 1 ]; then
		for ((i = ${seen:-0}; i < ${#lines[@]}; i++)); do show "${lines[i]}" "$s"; done
	fi
	p=0; f=0; k=0
	for l in "${lines[@]}"; do
		case $l in *PASS) p=$((p + 1)) ;; *FAIL) f=$((f + 1)) ;; *SKIP) k=$((k + 1)) ;; esac
	done
	note=
	if [ $rc -eq 124 ]; then
		note="timed out after ${TIMEOUT}s"; f=$((f + 1)); show "suite timed out after ${TIMEOUT}s FAIL" "$s"
	elif [ $((p + f + k)) -eq 0 ] && grep -qiE 'must be run as root|need(s)? root' "$log"; then
		note="needs root"; k=$((k + 1)); show "suite (needs root) SKIP" "$s"
	elif [ $((p + f + k)) -eq 0 ] && grep -qE 'No module named .?(pytest|scapy)' "$log"; then
		note="needs pytest and scapy"; k=$((k + 1)); show "suite (needs pytest and scapy) SKIP" "$s"
	elif [ $rc -ne 0 ] && [ $f -eq 0 ]; then
		note="exited $rc without a FAIL line"; f=$((f + 1)); show "suite exited with status $rc FAIL" "$s"
	fi
	TOTAL_P=$((TOTAL_P + p)); TOTAL_F=$((TOTAL_F + f)); TOTAL_S=$((TOTAL_S + k))
	SUMMARY+=("$s|$p|$f|$k|${elapsed}s${note:+, $note}")
done

echo
echo -e "${BOLD}Summary${NC}                 pass  fail  skip"
for row in "${SUMMARY[@]}"; do
	IFS='|' read -r s p f k note <<< "$row"
	c=$NC; [ "$f" -gt 0 ] && c=$RED
	printf "  %-20s %6s %b%5s%b %5s   %s\n" "$s" "$p" "$c" "$f" "$NC" "$k" "$note"
done
c=$GREEN; [ $TOTAL_F -gt 0 ] && c=$RED
printf "  %-20s %6s %b%5s%b %5s\n" "TOTAL" "$TOTAL_P" "$c" "$TOTAL_F" "$NC" "$TOTAL_S"
echo "Logs: $LOGDIR"
[ $TOTAL_F -eq 0 ]
