#!/bin/bash
# Tests for include, const, define, repeat and when.
# The expansion and error tests need no privileges; the kernel test needs root.

cd "$(dirname "$0")/.." || exit 1
BPFC=$PWD/bpfc

RED='\e[31m'
GREEN='\e[32m'
NC='\e[0m'
FAILED=0

function test_pass() { echo -e "$@ ${GREEN}PASS${NC}"; }
function test_fail() { echo -e "$@ ${RED}FAIL${NC}"; FAILED=1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/lib" "$TMP/inc"

# expect_expand <name> <expected output> <bpfc args...>
function expect_expand() {
	local name=$1 want=$2; shift 2
	local got
	got=$(cd "$TMP" && "$BPFC" -E "$@" 2>&1)
	if [ "$got" == "$want" ]; then
		test_pass "$name"
	else
		test_fail "$name"
		echo "--- want"; echo "$want"; echo "--- got"; echo "$got"
	fi
}

# expect_error <name> <message substring> <bpfc args...>
function expect_error() {
	local name=$1 want=$2; shift 2
	local got rc
	got=$(cd "$TMP" && "$BPFC" -E "$@" 2>&1); rc=$?
	if [ $rc -ne 0 ] && [[ "$got" == *"$want"* ]]; then
		test_pass "$name"
	else
		test_fail "$name"
		echo "--- want exit != 0 and '$want'; got exit $rc:"; echo "$got"
	fi
}

# ---------------- expansion ----------------

expect_expand PP-passthrough $'match tcp;\nmatch tcp-dst 23;\ndrop;' \
	"match tcp; match tcp-dst 23; drop"

expect_expand PP-comments $'match tcp;\ndrop;' \
	"# note; match tcp; #another; drop"

expect_expand PP-const $'set val X 34997;\nset val Y 0x88B5;\nset src-mac aa:bb:cc:dd:ee:ff;' \
	'const A 0x8800 + 0xB5; const B 0x88B5; const MAC aa:bb:cc:dd:ee:ff; set val X $A; set val Y $B; set src-mac $MAC'

expect_expand PP-const-override $'set val X 7;' \
	-s N=7 'const N 3; set val X $N'

expect_expand PP-expr $'set val X 4;\nset val X 255;\nset val X 1;\nset val X -3;\nset val X 16384;' \
	'set val X $(14 / 3); set val X $(0xff & ~0); set val X $(2 < 3 && 3 <= 3); set val X $(-7 % 4); set val X $(1 << 14)'

expect_expand PP-dollar $'debug-log cost$5;' \
	'debug-log cost$$5'

expect_expand PP-repeat $'get bytes 14 4 W0;\nget bytes 18 4 W1;\nget bytes 22 4 W2;' \
	'repeat 3 as I; get bytes $(14 + I*4) 4 W$I; end-repeat'

expect_expand PP-repeat-zero $'drop;' \
	'repeat 0 as I; set val X $I; end-repeat; drop'

expect_expand PP-repeat-nested $'set val X 00;\nset val X 01;\nset val X 10;\nset val X 11;' \
	'repeat 2 as I; repeat 2 as J; set val X $I$J; end-repeat; end-repeat'

expect_expand PP-repeat-runtime $'match val %N le 0;\ngoto __rep1_end;\nend-match;\nset val X 0;\nmatch val %N le 1;\ngoto __rep1_end;\nend-match;\nset val X 1;\nlabel __rep1_end;' \
	'repeat %N max 2 as I; set val X $I; end-repeat'

expect_expand PP-break-next $'match val %W eq 0;\ngoto __rep1_end;\nend-match;\ngoto __rep1_0;\nlabel __rep1_0;\nmatch val %W eq 0;\ngoto __rep1_end;\nend-match;\ngoto __rep1_1;\nlabel __rep1_1;\nlabel __rep1_end;' \
	'repeat 2; match val %W eq 0; break-repeat; end-match; next-repeat; end-repeat'

expect_expand PP-define $'set val OUT 65856;\nset val X 1;' \
	'define mpls-word V LABEL BOS TTL; set val $V $(($LABEL << 12) | ($BOS << 8) | $TTL); end-define; mpls-word OUT 16 1 64; set val X 1'

expect_expand PP-define-unique $'label skip_1;\nlabel skip_2;' \
	'define here; label skip_$UNIQUE; end-define; here; here'

expect_expand PP-define-repeat $'set val X 0;\nset val X 2;\nset val X 4;' \
	'define evens N; repeat $N as I; set val X $(I * 2); end-repeat; end-define; evens 3'

expect_expand PP-when $'drop;\ncontinue;' \
	'const MODE 2; when $MODE == 2; drop; otherwise; accept; end-when; when defined(NOPE); accept; otherwise; continue; end-when'

expect_expand PP-when-repeat $'set val X 1;\nset val X 3;' \
	'repeat 4 as I; when I % 2; set val X $I; end-when; end-repeat'

cat > "$TMP/lib/a.bpfc" <<'EOF'
# library
const ETYPE 0x88B5;
define set-type;
  set eth-proto $ETYPE;
end-define;
EOF
printf 'include ../lib/a.bpfc;\nset val X 2;\n' > "$TMP/inc/b.bpfc"
printf 'include a.bpfc;\nset val X 3;\nset-type;\n' > "$TMP/inc/c.bpfc"
expect_expand PP-include $'set eth-proto 0x88B5;' \
	'include lib/a.bpfc; include "lib/a.bpfc"; set-type'
printf 'include inc/b.bpfc;\nset val X 1;\n' > "$TMP/main.bpfc"
expect_expand PP-include-relative $'set val X 2;\nset val X 1;' -f main.bpfc
expect_expand PP-include-path $'set val X 3;\nset eth-proto 0x88B5;' -L lib -f inc/c.bpfc
expect_expand PP-stdin $'drop;' -f - <<< 'repeat 1; drop; end-repeat'

# ---------------- errors ----------------

expect_error PP-err-undefined 'undefined $NOPE' 'set val X $NOPE'
expect_error PP-err-line '<command line>:3: undefined $NOPE' $'match tcp;\n\nset val X $NOPE'
expect_error PP-err-break 'break-repeat outside a repeat' 'break-repeat'
expect_error PP-err-unclosed 'repeat without end-repeat' 'repeat 2; drop'
expect_error PP-err-stray 'end-repeat without a matching opening command' 'drop; end-repeat'
expect_error PP-err-count 'repeat count 5000 is not 0-4096' 'repeat 5000; end-repeat'
expect_error PP-err-args 'macro m takes 2 arguments' 'define m A B; drop; end-define; m 1'
expect_error PP-err-reserved "'drop' is a bpfc command" 'define drop; end-define'
expect_error PP-err-recursive 'nested more than' 'define r; r; end-define; r'
expect_error PP-err-redefine 'const N is already defined' 'const N 1; const N 2'
expect_error PP-err-macro-twice 'macro m is already defined' 'define m; end-define; define m; end-define'
expect_error PP-err-include 'include file' 'include nope.bpfc'
expect_error PP-err-div0 'division by zero' 'set val X $(1 / 0)'
expect_error PP-err-not-number "MAC is 'aa:bb', not a number" 'const MAC aa:bb; set val X $(MAC + 1)'
expect_error PP-err-macro-trace 'in macro m called from <command line>:1' 'define m; set val X $Q; end-define; m'

# ---------------- bytecode ----------------
# An unrolled repeat compiles to the same instructions as the same code written out.

(
	cd "$TMP" || exit 1
	"$BPFC" "decl W 4; decl S 8; repeat 4 as I; get bytes \$(14 + I*4) 4 W; calc add S %W; end-repeat" >/dev/null && mv output.bpf rep.bpf
	"$BPFC" "decl W 4; decl S 8; get bytes 14 4 W; calc add S %W; get bytes 18 4 W; calc add S %W; get bytes 22 4 W; calc add S %W; get bytes 26 4 W; calc add S %W" >/dev/null && mv output.bpf flat.bpf
	cmp -s rep.bpf flat.bpf
) && test_pass PP-bytecode-same || test_fail PP-bytecode-same

# ---------------- kernel ----------------
# ICMP echo requests carry N in payload byte 60 (ping -p fills it). Per request:
#   RUNS += min(N, 8)          repeat %N max 8
#   BRK  += min(N + 1, 8)      repeat 8, break-repeat once I == N
#   NXT  += 6 - min(N, 6)      repeat 6, next-repeat while N > I
#   NEST[k] += 1 << k          nested repeat, k = I*2 + J

if [ "$(id -u)" != 0 ]; then
	echo "kernel tests skipped (need root)"
	exit $FAILED
fi

ulimit -l unlimited 2>/dev/null
ip netns add PPA
ip netns add PPB
ip link add ppa netns PPA type veth peer name ppb netns PPB
ip -n PPA link set ppa up
ip -n PPB link set ppb up
ip -n PPA addr add 10.9.0.1/24 dev ppa
ip -n PPB addr add 10.9.0.2/24 dev ppb
mkdir -p /var/run/bpf/PPB
umount /var/run/bpf/PPB &>/dev/null
mount -t bpf bpffs /var/run/bpf/PPB

cat > "$TMP/kern.bpfc" <<'EOF'
const MAXN 8;
define count MAP KEY;
  calc-map add $MAP $KEY 1;
end-define;
match icmp;
  match icmp-type 8;
    decl N 4;
    get bytes 60 1 N;
    repeat %N max $MAXN as I;
      count RUNS 0;
    end-repeat;
    repeat $MAXN as I;
      count BRK 0;
      match val %N eq $I;
        break-repeat;
      end-match;
    end-repeat;
    repeat 6 as I;
      match val %N gt $I;
        next-repeat;
      end-match;
      count NXT 0;
    end-repeat;
    repeat 3 as I;
      repeat 2 as J;
        calc-map add NEST $(I*2 + J) $(1 << (I*2 + J));
      end-repeat;
    end-repeat;
  end-match;
end-match
EOF

function map_value() {   # map key -> value in hex, as bpfc -r prints it
	ip netns exec PPB "$BPFC" -m /var/run/bpf/PPB -r "$1" | grep "Key: $(printf '0x%016x' "$2")" | sed 's/.*Value: //'
}

if ip netns exec PPB "$BPFC" -i ppb -p 5 -m /var/run/bpf/PPB -f "$TMP/kern.bpfc" >/dev/null; then
	test_pass PP-kernel-load
	ip netns exec PPA ping -c 2 -i 0.2 -W 1 -p 03 10.9.0.2 &>/dev/null
	ip netns exec PPA ping -c 1 -W 1 -p 0c 10.9.0.2 &>/dev/null
	# N=3 twice, N=12 once
	[ "$(map_value RUNS 0)" == "$(printf '0x%016x' 14)" ] && test_pass PP-kernel-runtime-count || test_fail PP-kernel-runtime-count "(RUNS=$(map_value RUNS 0))"
	[ "$(map_value BRK 0)" == "$(printf '0x%016x' 16)" ] && test_pass PP-kernel-break || test_fail PP-kernel-break "(BRK=$(map_value BRK 0))"
	[ "$(map_value NXT 0)" == "$(printf '0x%016x' 6)" ] && test_pass PP-kernel-next || test_fail PP-kernel-next "(NXT=$(map_value NXT 0))"
	[ "$(map_value NEST 5)" == "$(printf '0x%016x' 96)" ] && test_pass PP-kernel-nested || test_fail PP-kernel-nested "(NEST[5]=$(map_value NEST 5))"
else
	test_fail PP-kernel-load
fi

umount /var/run/bpf/PPB
ip netns del PPA
ip netns del PPB
exit $FAILED
