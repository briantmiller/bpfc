#!/bin/bash
# Tests for the stack layout: variables take as many slots as the program
# declares, and instructions fit their scratch space into what is left.
# The compile tests need no privileges; the kernel tests need root.

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

# expect_compile <name> <program>
function expect_compile() {
	local out
	if out=$(cd "$TMP" && "$BPFC" "$2" 2>&1); then test_pass "$1"; else test_fail "$1"; echo "$out"; fi
}
# expect_error <name> <message substring> <program>
function expect_error() {
	local out
	if out=$(cd "$TMP" && "$BPFC" "$3" 2>&1); then test_fail "$1"; echo "compiled, expected '$2'";
	elif [[ "$out" == *"$2"* ]]; then test_pass "$1"; else test_fail "$1"; echo "$out"; fi
}

expect_compile ST-48-vars          'repeat 48 as I; decl V$I 8; end-repeat'
expect_error   ST-49-vars          "no stack left for variable 'V48'" 'repeat 49 as I; decl V$I 8; end-repeat'
expect_compile ST-free-reuse       'repeat 48 as I; decl V$I 8; end-repeat; free V47; decl Z 4'
expect_compile ST-csum-small-room  'repeat 47 as I; decl V$I 8; end-repeat; recalc-udp-csum'
expect_error   ST-fib-no-room      'fib-lookup needs 72 bytes' 'repeat 41 as I; decl V$I 8; end-repeat; fib-lookup 10.0.0.1'
# 16-byte variables (IPv6 addresses) take two slots: 24 of them fill the stack
expect_compile ST-16-byte-vars     'repeat 24 as I; decl V$I 16; end-repeat'
expect_error   ST-16-byte-vars-full "no stack left for variable 'V24'" 'repeat 25 as I; decl V$I 16; end-repeat'
expect_compile ST-16-byte-reuse    'repeat 24 as I; decl V$I 16; end-repeat; free V23; decl Z 16'
expect_error   ST-16-byte-no-8-reuse "no stack left for variable 'Z'" 'repeat 48 as I; decl V$I 8; end-repeat; free V47; decl Z 16'
# push-eth used to keep its 32 bytes of scratch for the rest of the program
expect_compile ST-scratch-released 'repeat 20; push-eth aa:bb:cc:dd:ee:ff 11:22:33:44:55:66; end-repeat; repeat 40 as I; decl V$I 8; end-repeat'

if [ "$(id -u)" != 0 ]; then
	echo "ST-kernel tests (need root) SKIP"
	exit $FAILED
fi

# Creating the buffer map needs root, even when compiling only.
expect_error   ST-xor-no-room      'xor-packet needs at least 8 bytes' \
	'shared-buffer-map SB 4 512; repeat 48 as I; decl V$I 8; end-repeat; xor-packet-keyed SB 0 64 42 0'

ulimit -l unlimited 2>/dev/null
ip netns add STA
ip netns add STB
ip link add sta netns STA type veth peer name stb netns STB
ip -n STA link set sta up
ip -n STB link set stb up
ip -n STA addr add 10.6.0.1/24 dev sta
ip -n STB addr add 10.6.0.2/24 dev stb
ip -n STA neigh replace 10.6.0.2 lladdr "$(ip -n STB -br link show stb | awk '{print $3}')" dev sta nud permanent
ip netns exec STA ethtool -K sta tx off >/dev/null 2>&1   # full UDP checksums on the wire
mkdir -p /var/run/bpf/STA /var/run/bpf/STB
for n in STA STB; do umount /var/run/bpf/$n &>/dev/null; mount -t bpf bpffs /var/run/bpf/$n; done

function map_value() {   # ns map key
	ip netns exec "$1" "$BPFC" -m /var/run/bpf/"$1" -r "$2" | grep "Key: $(printf '0x%016x' "$3")" | sed 's/.*Value: //'
}
function hex() { printf '0x%016x' "$1"; }

# fib-lookup used to overwrite the two variables declared just before it.
ip netns exec STA "$BPFC" -i sta -d egress -p 3 -m /var/run/bpf/STA "match icmp; decl A 8; decl B 8; decl C 8; \
	set val A 1111; set val B 2222; set val C 3333; fib-lookup 10.6.0.2; \
	set map FIB 1 %A; set map FIB 2 %B; set map FIB 3 %C; set map FIB 9 %FIB_RESULT" >/dev/null
ip netns exec STA ping -c 1 -W 1 10.6.0.2 &>/dev/null
[ "$(map_value STA FIB 1)$(map_value STA FIB 2)$(map_value STA FIB 3)" == "$(hex 1111)$(hex 2222)$(hex 3333)" ] \
	&& test_pass ST-kernel-fib-keeps-vars || test_fail ST-kernel-fib-keeps-vars "(B=$(map_value STA FIB 2) C=$(map_value STA FIB 3))"
[ "$(map_value STA FIB 9)" == "$(hex 0)" ] && test_pass ST-kernel-fib-result || test_fail ST-kernel-fib-result

# 42 variables: the UDP checksum and XOR work in 32-byte chunks instead of 256.
cat > "$TMP/many.bpfc" <<'EOF'
shared-buffer-map SB 4 512;
repeat 40 as I;
  decl V$I 8;
  set val V$I $(I * 7 + 1);
end-repeat;
decl W 8;
match udp;
  match udp-dst 9999;
    calc-csum udp CS;
    get bytes 40 2 PKT;
    set map ST 1 %CS;
    set map ST 2 %PKT;
    set map ST 3 %V39;
    zero-buffer-keyed SB 0 256 0;
    xor-packet-keyed SB 0 100 42 0;
    repeat 13 as K;
      load-packet-keyed SB 0 8 $(K * 8 < 92 ? K * 8 : 92) 42;
      get bytes 42 8 W;
      set map XB $K %W;
    end-repeat;
  end-match;
end-match
EOF
if ip netns exec STB "$BPFC" -i stb -p 5 -m /var/run/bpf/STB -f "$TMP/many.bpfc" >/dev/null; then
	test_pass ST-kernel-42-vars-load
	ip netns exec STA python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(bytes((i * 37 + 5) & 255 for i in range(100)), ('10.6.0.2', 9999))"
	sleep 0.3
	[ -n "$(map_value STB ST 1)" ] && [ "$(map_value STB ST 1)" == "$(map_value STB ST 2)" ] \
		&& test_pass ST-kernel-csum-small-chunks || test_fail ST-kernel-csum-small-chunks "(computed $(map_value STB ST 1), packet $(map_value STB ST 2))"
	[ "$(map_value STB ST 3)" == "$(hex 274)" ] && test_pass ST-kernel-vars-intact || test_fail ST-kernel-vars-intact
	want=$(python3 -c "
p = bytes((i * 37 + 5) & 255 for i in range(100))
print(' '.join('0x%016x' % int.from_bytes(p[min(k * 8, 92):min(k * 8, 92) + 8], 'big') for k in range(13)))")
	got=$(for k in $(seq 0 12); do map_value STB XB $k; done | tr '\n' ' ' | sed 's/ $//')
	[ "$got" == "$want" ] && test_pass ST-kernel-xor-small-chunks || test_fail ST-kernel-xor-small-chunks
else
	test_fail ST-kernel-42-vars-load
fi

for n in STA STB; do umount /var/run/bpf/$n; done
ip netns del STA
ip netns del STB
exit $FAILED
