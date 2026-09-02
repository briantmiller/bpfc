#!/bin/bash

if [ $(whoami) != "root" ]
then
	echo "Must be run as root"
	exit 1
fi

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


# Color Definitions
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m' # No Color (Reset)

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

function test_pass()
{
	echo -e "$@ ${GREEN}PASS${NC}"
}

function test_fail()
{
	echo -e "$@ ${RED}FAIL${NC}"
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
ip netns exec WAN ncat -l 7 --keep-open --udp --exec "/bin/cat" &
UDP_PID=$!

#Test bed validation
ip netns exec RTR   ping -c 4 -i 0.1 -W 0.2 10.0.0.1    &>/dev/null && test_pass RTR-WAN   || test_fail RTR-WAN &
ip netns exec HOST1 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST1-RTR || test_fail HOST1-RTR &
ip netns exec HOST2 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST2-RTR || test_fail HOST2-RTR &

#ICMP NAT testing
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d egress -p 100 -m /var/run/bpf/RTR 'match icmp; match icmp-type 8; get ip-src IP_SRC; get bytes 38 2 ICMP_IDENT; set map ICMP_NAT %ICMP_IDENT %IP_SRC; set ip-src 10.0.0.30' && test_pass ICMP-NAT-OUT || test_fail ICMP-NAT-OUT
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d ingress -p 100 -m /var/run/bpf/RTR 'match icmp; match icmp-type 0; get bytes 38 2 ICMP_IDENT; get map ICMP_NAT %ICMP_IDENT IP_DST; set ip-dst %IP_DST' && test_pass ICMP-NAT-IN || test_fail ICMP-NAT-IN

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
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d egress -p 106 -m /var/run/bpf/RTR 'match tcp; match tcp-flags SYN; get ip-src IP_SRC; get tcp-src TCP_SRC; set map TCP_NAT %TCP_SRC %IP_SRC' && test_pass TCP-NAT-OUT || test_fail TCP-NAT-OUT
#Change all outgoing TCP packets to be sourced from wan interface
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d egress -p 1061 -m /var/run/bpf/RTR 'match tcp; set ip-src 10.0.0.30' && test_pass TCP-NAT-OUT || test_fail TCP-NAT-OUT
#Change the IP destination of TCP packets back to NAT'ed address
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d ingress -p 106 -m /var/run/bpf/RTR 'match tcp; get tcp-dst TCP_DST; get map TCP_NAT %TCP_DST IP_DST; set ip-dst %IP_DST' && test_pass TCP-NAT-IN || test_fail TCP-NAT-IN

echo "TCP Echo" | timeout 4 ip netns exec HOST1 nc -w 1 10.0.01 7 && test_pass TCP-NAT || test_fail TCP-NAT


#UDP NAT testing

ip netns exec RTR ./bpf_compiler $COPTS -i wan -d egress -p 117 -m /var/run/bpf/RTR 'match udp; get ip-src IP_SRC; get udp-src UDP_SRC; set map UDP_NAT %UDP_SRC %IP_SRC;set ip-src 10.0.0.30' && test_pass UDP-NAT-OUT || test_fail UDP-NAT-OUT
ip netns exec RTR ./bpf_compiler $COPTS -i wan -d ingress -p 117 -m /var/run/bpf/RTR 'match udp; get udp-dst UDP_DST; get map UDP_NAT %UDP_DST IP_DST; set ip-dst %IP_DST' && test_pass UDP-NAT-IN || test_fail UDP-NAT-IN

timeout 5 ip netns exec HOST1 tcpdump -c 1 -lvnpi rtr udp and ip src 10.0.0.1 &>/dev/null && test_pass UDP-NAT || test_fail UDP-NAT &
sleep 0.5s 

echo "UDP Echo" | timeout 4 ip netns exec HOST1 ncat -u 10.0.0.1 7 
#&& test_pass UDP-NAT || test_fail UDP-NAT


#Test bed cleanup
kill -9 $TCP_PID &>/dev/null 
kill -9 $UDP_PID &>/dev/null 
wait &>/dev/null
ip netns del RTR
ip netns del WAN
ip netns del HOST1
ip netns del HOST2
