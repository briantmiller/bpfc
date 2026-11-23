#!/bin/bash
#
# make coverage: runs the test suites against a gcov build of bpfc and
# reports bpfc.c's line, function and branch coverage.
#
#   make coverage [COVERAGE_SUITES="compile preprocessor ..."] [TESTFLAGS=-f]
#                 [COVERAGE_MIN_LINES=N] [COVERAGE_MIN_BRANCHES=N]
#
# The Makefile has already built ./bpfc with --coverage, its object in
# coverage/. This script runs the suites (all of them unless
# COVERAGE_SUITES names some; needs root for most), writes
#   coverage/index.html     line-by-line report
#   coverage/summary.txt    the totals
#   coverage/coverage.json  gcovr tracefile, to merge runs from other machines:
#     gcovr --add-tracefile a.json --add-tracefile b.json --html-details merged.html
# and rebuilds the normal ./bpfc. It fails when a suite failed or coverage
# is below COVERAGE_MIN_LINES / COVERAGE_MIN_BRANCHES (percent; give 0 to
# skip the check, e.g. with a partial COVERAGE_SUITES).
#
# Needs gcovr (pip install gcovr).

cd "$(dirname "$0")/.." || exit 1

MIN_LINES=${COVERAGE_MIN_LINES:-0}
MIN_BRANCHES=${COVERAGE_MIN_BRANCHES:-0}

rebuild() { rm -f bpfc; make -s bpfc >/dev/null; }
trap rebuild EXIT

command -v gcovr >/dev/null || { echo "gcovr not found: pip install gcovr"; exit 1; }
[ -f coverage/bpfc.gcno ] || { echo "no coverage build (run make coverage)"; exit 1; }

# The counters are written by every bpfc process, including frontends'
# children, which run as user bpfc or nobody: coverage/bpfc.gcda must be
# writable by them. It is created once here with mode 0666; later runs
# update it in place. (Not umask 0 for the suites: the files they create
# would be world-writable, which bpfc and bpfcd refuse.)
rm -f coverage/*.gcda
(umask 0; ./bpfc -h >/dev/null)

built=$(sha256sum bpfc)
# shellcheck disable=SC2086
bash tests/run-tests.sh $TESTFLAGS $COVERAGE_SUITES
tests_rc=$?
# A suite that runs make (install) rebuilds bpfc when bpfc.c is newer,
# e.g. edited during the run: what ran after that was not counted.
if [ "$(sha256sum bpfc)" != "$built" ]; then
	echo "coverage: bpfc was rebuilt during the run (bpfc.c changed?); the report misses what ran afterwards"
	tests_rc=1
fi

if [ ! -f coverage/bpfc.gcda ]; then
	echo "no coverage data written (coverage/bpfc.gcda)"; exit 1
fi

opts=(-r . --filter 'bpfc\.c$' coverage)
gcovr "${opts[@]}" --html-details coverage/index.html --json coverage/coverage.json \
      --txt coverage/summary.txt --print-summary >/dev/null 2>coverage/gcovr.log
gcovr "${opts[@]}" --print-summary 2>>coverage/gcovr.log | tail -3 | tee -a coverage/summary.txt
echo "Report: coverage/index.html"

rc=0
[ $tests_rc -eq 0 ] || { echo "coverage: some tests failed"; rc=1; }
if [ "$MIN_LINES" != 0 ] || [ "$MIN_BRANCHES" != 0 ]; then
	if ! gcovr "${opts[@]}" --fail-under-line "$MIN_LINES" --fail-under-branch "$MIN_BRANCHES" \
	        >/dev/null 2>>coverage/gcovr.log; then
		echo "coverage: below the minimum (lines $MIN_LINES %, branches $MIN_BRANCHES %)"; rc=1
	fi
fi
exit $rc
