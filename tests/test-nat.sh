#!/bin/bash

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root nat
require_cmds nat ping nc ncat tcpdump

sysctl net.ipv4.ip_forward=1 &>/dev/null

DEBUG=0
declare -a TESTS
#TESTS=()
while [ "$1" != "" ]
do
	ARG="$1"
	shift
	if [ "$ARG" == "-d" ]
	then
		DEBUG=1
	else
		TESTS+=("$ARG")
	fi
done
COPTS=""
[ $DEBUG -eq 1 ] && COPTS=" -v "



TEST=""

function test_enabled()
{
	T="$1"
	[ "$TESTS" == "" ] && return 0
	for element in "${TESTS[@]}"; do
    		if [[ "$element" == "$T" ]]; then
			TEST="$T"
			return 0
		fi
	done
	return 1
}



#Setup network
ulimit -l unlimited
ip netns add RTR
ip netns add WAN
ip netns add HOST1
ip netns add HOST2
ip -n RTR link set lo up
ip -n WAN link set lo up
ip -n HOST1 link set lo up
ip -n HOST2 link set lo up
ip netns exec RTR mkdir -p /var/run/bpf/RTR
umount /var/run/bpf/RTR &>/dev/null
mount -t bpf bpffs /var/run/bpf/RTR
ip link add wan netns RTR type veth peer name rtr netns WAN
ip link add host1 netns RTR type veth peer name rtr netns HOST1
ip link add host2 netns RTR type veth peer name rtr netns HOST2
ip -n RTR link add br0 type bridge
ip -n RTR link set host1 master br0
ip -n RTR link set host2 master br0

for I in wan host1 host2 br0
do
	ip -n RTR link set $I up
done
ip -n WAN link set rtr up
ip -n HOST1 link set rtr up
ip -n HOST2 link set rtr up

ip -n WAN addr add 10.0.0.1/24 dev rtr
ip -n RTR addr add 10.0.0.30/24 dev wan
ip -n RTR addr add 192.168.0.1/24 dev br0
ip -n HOST1 addr add 192.168.0.50/24 dev rtr
ip -n HOST2 addr add 192.168.0.80/24 dev rtr

ip -n WAN route add default via 10.0.0.1
ip -n HOST1 route add default via 192.168.0.1
ip -n HOST2 route add default via 192.168.0.1

ip netns exec WAN nc -kl 7 &>/dev/null &
TCP_PID=$!
ip netns exec WAN ncat -l 7 --keep-open --udp --exec "/bin/cat" &>/dev/null &
UDP_PID=$!

#Test bed validation
ip netns exec RTR   ping -c 4 -i 0.1 -W 0.2 10.0.0.1    &>/dev/null && test_pass RTR-WAN   || test_fail RTR-WAN & P1=$!
ip netns exec HOST1 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST1-RTR || test_fail HOST1-RTR & P2=$!
ip netns exec HOST2 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST2-RTR || test_fail HOST2-RTR & P3=$!

wait $P1 $P2 $P3
# WAN has no route back to 192.168.0.0/24: without NAT, HOST1 cannot reach it.
# (This makes the NAT checks below meaningful.)
timeout 3 ip netns exec HOST1 ping -c 1 -W 1 10.0.0.1 &>/dev/null && test_fail NAT-required || test_pass NAT-required

#ICMP NAT testing
ip netns exec RTR ./bpfc $COPTS -i wan -d egress -p 100 -m /var/run/bpf/RTR 'match icmp; match icmp-type 8; get ip-src IP_SRC; get bytes 38 2 ICMP_IDENT; set map ICMP_NAT %ICMP_IDENT %IP_SRC; set ip-src 10.0.0.30' && test_pass ICMP-NAT-OUT || test_fail ICMP-NAT-OUT
ip netns exec RTR ./bpfc $COPTS -i wan -d ingress -p 100 -m /var/run/bpf/RTR 'match icmp; match icmp-type 0; get bytes 38 2 ICMP_IDENT; get map ICMP_NAT %ICMP_IDENT IP_DST; set ip-dst %IP_DST' && test_pass ICMP-NAT-IN || test_fail ICMP-NAT-IN

#timeout 5 ip netns exec RTR tcpdump -lvnpi wan icmp -XX &
#timeout 5 ip netns exec RTR tcpdump -lvnpi wan tcp &
#timeout 8 ip netns exec RTR tcpdump -lvnpi wan udp &
#timeout 8 ip netns exec WAN tcpdump -lvnpi rtr udp &
#timeout 8 ip netns exec HOST1 tcpdump -lvnpi rtr udp &
#sleep 0.5s

ip netns exec HOST1 ping -c 3 10.0.0.1 &>/dev/null && test_pass ICMP-NAT || test_fail ICMP-NAT

#TODO: Use destination IP and per-protocol identifier (ICMP_IDEN, TCP_SRC, UDP_SRC) together to build a better NAT table
#TODO: Detect TCP FIN packet and clear/delete map entry or just set to zero


#TCP NAT testing

#Register new TCP connections into TCP NAT table
ip netns exec RTR ./bpfc $COPTS -i wan -d egress -p 106 -m /var/run/bpf/RTR 'match tcp; match tcp-flags SYN; get ip-src IP_SRC; get tcp-src TCP_SRC; set map TCP_NAT %TCP_SRC %IP_SRC' && test_pass TCP-NAT-OUT || test_fail TCP-NAT-OUT
#Change all outgoing TCP packets to be sourced from wan interface
ip netns exec RTR ./bpfc $COPTS -i wan -d egress -p 1061 -m /var/run/bpf/RTR 'match tcp; set ip-src 10.0.0.30' && test_pass TCP-NAT-OUT-2 || test_fail TCP-NAT-OUT-2
#Change the IP destination of TCP packets back to NAT'ed address
ip netns exec RTR ./bpfc $COPTS -i wan -d ingress -p 106 -m /var/run/bpf/RTR 'match tcp; get tcp-dst TCP_DST; get map TCP_NAT %TCP_DST IP_DST; set ip-dst %IP_DST' && test_pass TCP-NAT-IN || test_fail TCP-NAT-IN

echo "TCP Echo" | timeout 4 ip netns exec HOST1 nc -w 1 10.0.0.1 7 &>/dev/null && test_pass TCP-NAT || test_fail TCP-NAT


#UDP NAT testing

ip netns exec RTR ./bpfc $COPTS -i wan -d egress -p 117 -m /var/run/bpf/RTR 'match udp; get ip-src IP_SRC; get udp-src UDP_SRC; set map UDP_NAT %UDP_SRC %IP_SRC;set ip-src 10.0.0.30' && test_pass UDP-NAT-OUT || test_fail UDP-NAT-OUT
ip netns exec RTR ./bpfc $COPTS -i wan -d ingress -p 117 -m /var/run/bpf/RTR 'match udp; get udp-dst UDP_DST; get map UDP_NAT %UDP_DST IP_DST; set ip-dst %IP_DST' && test_pass UDP-NAT-IN || test_fail UDP-NAT-IN

timeout 5 ip netns exec HOST1 tcpdump -c 1 -lvnpi rtr udp and ip src 10.0.0.1 &>/dev/null && test_pass UDP-NAT || test_fail UDP-NAT &
sleep 0.5s 

echo "UDP Echo" | timeout 4 ip netns exec HOST1 ncat -u 10.0.0.1 7 &>/dev/null


#The README's NAT (Advanced Examples 4), as printed there: its bpfc commands
#are taken from README.md and run with eth0 replaced by wan.
ip netns exec RTR ./bpfc -i wan -c &>/dev/null
readme_nat() {
	python3 - "$1" <<'PY'
import re, sys
t = open("README.md").read()
sec = t[t.index("### 4. Network Address Translation (NAT)"):t.index("### 5.")]
for blk in re.findall(r"```bash\n(.*?)```", sec, re.S):
    blk = blk.replace("\\\n", " ")
    for line in blk.splitlines():
        line = line.strip()
        if line.startswith("bpfc "):
            print(line[5:])
PY
}
if command -v python3 >/dev/null; then
	n=0
	while IFS= read -r cmd; do
		eval "set -- $cmd"
		args=()
		for a; do [ "$a" = eth0 ] && a=wan; args+=("$a"); done
		ip netns exec RTR ./bpfc -m /var/run/bpf/RTR "${args[@]}" >/dev/null || { test_fail "NAT-README-LOAD ($cmd)"; }
		n=$((n + 1))
	done < <(readme_nat)
	[ $n -eq 7 ] && test_pass "NAT-README-LOAD ($n programs)" || test_fail "NAT-README-LOAD ($n programs, expected 7)"
	ip netns exec HOST1 ping -c 3 10.0.0.1 &>/dev/null && test_pass NAT-README-ICMP || test_fail NAT-README-ICMP
	echo "TCP Echo" | timeout 4 ip netns exec HOST1 nc -w 1 10.0.0.1 7 &>/dev/null && test_pass NAT-README-TCP || test_fail NAT-README-TCP
	timeout 5 ip netns exec HOST1 tcpdump -c 1 -lvnpi rtr udp and ip src 10.0.0.1 &>/dev/null && test_pass NAT-README-UDP || test_fail NAT-README-UDP &
	sleep 0.5s
	echo "UDP Echo" | timeout 4 ip netns exec HOST1 ncat -u 10.0.0.1 7 &>/dev/null
	wait $!
fi

#NAT written with pack (dist/examples/flow/nat-pack.bpfc), then with port
#translation (nat-pat.bpfc): the same checks, then two inside hosts using the
#same source port to the same server at the same time.
EXF=dist/examples/flow
ip netns exec RTR ./bpfc -i wan -c &>/dev/null
nat_load() {
	ip netns exec RTR ./bpfc $COPTS -i wan -d egress -p 100 -m /var/run/bpf/RTR -f $EXF/$1.bpfc >/dev/null &&
	ip netns exec RTR ./bpfc $COPTS -i wan -d ingress -p 100 -m /var/run/bpf/RTR -f $EXF/$1.bpfc >/dev/null
}
# Two clients, one per inside host, both from source port $2, talk to the
# WAN server at once; prints what each got back ("H1 H2" when both got their own).
same_port() {
	local proto=$1 port=$2 out1 out2
	out1=$(mktemp); out2=$(mktemp)
	for h in 1 2; do
		ip netns exec HOST$h timeout 5 python3 -c '
import socket, sys
proto, port, me = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", port)); s.settimeout(3)
dst = ("10.0.0.1", 9 if proto == "udp" else 10)
if proto == "udp": s.sendto(me.encode(), dst)
else: s.connect(dst); s.send(me.encode())
try: print(s.recv(100).decode())
except Exception: print("-")' $proto $port H$h > $( [ $h = 1 ] && echo $out1 || echo $out2 ) 2>/dev/null &
		sleep 0.1
	done
	wait
	echo "$(cat $out1) $(cat $out2)"
	rm -f $out1 $out2
}
if command -v python3 >/dev/null; then
	# echo servers on WAN that answer after 1 s, so both clients have sent before any reply comes back
	ip netns exec WAN python3 -c '
import socket, threading, time
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("10.0.0.1", 9))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("10.0.0.1", 10)); t.listen(16)
def udp():
    while True:
        d, a = u.recvfrom(100)
        threading.Timer(1, u.sendto, (d, a)).start()
def tcp(c):
    d = c.recv(100); time.sleep(1); c.send(d); c.close()
threading.Thread(target=udp, daemon=True).start()
while True:
    c, a = t.accept(); threading.Thread(target=tcp, args=(c,), daemon=True).start()' &>/dev/null &
	SLOW_PID=$!
	sleep 0.5
fi

nat_load nat-pack && test_pass NAT-PACK-LOAD || test_fail NAT-PACK-LOAD
ip netns exec HOST1 ping -c 3 10.0.0.1 &>/dev/null && test_pass NAT-PACK-ICMP || test_fail NAT-PACK-ICMP
echo "TCP Echo" | timeout 4 ip netns exec HOST1 nc -w 1 10.0.0.1 7 &>/dev/null && test_pass NAT-PACK-TCP || test_fail NAT-PACK-TCP
timeout 5 ip netns exec HOST1 tcpdump -c 1 -lvnpi rtr udp and ip src 10.0.0.1 &>/dev/null && test_pass NAT-PACK-UDP || test_fail NAT-PACK-UDP &
sleep 0.5s
echo "UDP Echo" | timeout 4 ip netns exec HOST1 ncat -u 10.0.0.1 7 &>/dev/null
wait $!
if [ -n "$SLOW_PID" ]; then
	# the limitation nat-pat.bpfc removes: without port translation both replies
	# go to HOST2, which sent last, and HOST1 gets nothing
	R=$(same_port udp 5555)
	[ "${R%% *}" = "-" ] && test_pass "NAT-PACK-SAME-PORT-COLLIDES ($R)" || test_fail "NAT-PACK-SAME-PORT-COLLIDES ($R)"
fi

ip netns exec RTR ./bpfc -i wan -c &>/dev/null
nat_load nat-pat && test_pass NAT-PAT-LOAD || test_fail NAT-PAT-LOAD
ip netns exec HOST1 ping -c 3 10.0.0.1 &>/dev/null && test_pass NAT-PAT-ICMP || test_fail NAT-PAT-ICMP
echo "TCP Echo" | timeout 4 ip netns exec HOST1 nc -w 1 10.0.0.1 7 &>/dev/null && test_pass NAT-PAT-TCP || test_fail NAT-PAT-TCP
if [ -n "$SLOW_PID" ]; then
	R=$(same_port udp 5556)
	[ "$R" = "H1 H2" ] && test_pass "NAT-PAT-SAME-PORT-UDP ($R)" || test_fail "NAT-PAT-SAME-PORT-UDP ($R)"
	R=$(same_port tcp 5557)
	[ "$R" = "H1 H2" ] && test_pass "NAT-PAT-SAME-PORT-TCP ($R)" || test_fail "NAT-PAT-SAME-PORT-TCP ($R)"
	N=$(ip netns exec RTR ./bpfc -m /var/run/bpf/RTR -r PAT_IN | grep -c 'Key:')
	[ "$N" -ge 4 ] && test_pass "NAT-PAT-ENTRIES ($N flows)" || test_fail "NAT-PAT-ENTRIES ($N flows)"
	kill $SLOW_PID &>/dev/null
fi
ip netns exec RTR ./bpfc -i wan -c &>/dev/null

#Test bed cleanup
kill -9 $TCP_PID &>/dev/null 
kill -9 $UDP_PID &>/dev/null 
wait &>/dev/null
for C in RTR WAN HOST1 HOST2
do      
        umount /var/run/bpf/$C &>/dev/null
done
ip netns del RTR
ip netns del WAN
ip netns del HOST1
ip netns del HOST2

tests_exit
