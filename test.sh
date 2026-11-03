#!/bin/bash
# Runs the test suites and prints pass/fail/skip totals; see tests/run-tests.sh -h.
exec bash "$(dirname "$0")/tests/run-tests.sh" "$@"
