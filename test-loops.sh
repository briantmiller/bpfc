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
umount /var/run/bpf/RTR &>/dev/null
mount -t bpf bpffs /var/run/bpf/RTR
ip link add wan netns RTR type veth peer name rtr netns WAN
ip link add host1 netns RTR type veth peer name rtr netns HOST1
ip link add host2 netns RTR type veth peer name rtr netns HOST2

ip -n WAN link add lo0 type dummy

ip -n RTR link add br0 type bridge
ip -n RTR link set host1 master br0
ip -n RTR link set host2 master br0

for I in wan host1 host2 br0
do
	ip -n RTR link set $I up
done
ip -n WAN link set rtr up
ip -n WAN link set lo0 up
ip -n HOST1 link set rtr up
ip -n HOST2 link set rtr up

ip -n WAN addr add 10.0.0.1/24 dev rtr
ip -n WAN addr add 10.0.1.1/32 dev lo0
ip -n RTR addr add 10.0.0.30/24 dev wan
ip -n RTR addr add 192.168.0.1/24 dev br0
ip -n HOST1 addr add 192.168.0.50/24 dev rtr
ip -n HOST2 addr add 192.168.0.80/24 dev rtr

ip -n RTR route add default via 10.0.0.1
ip -n HOST1 route add default via 192.168.0.1
ip -n HOST2 route add default via 192.168.0.1

#ip -br -c -n WAN addr show
#ip -br -c -n RTR addr show
#ip -br -c -n RTR route

ip netns exec WAN nc -kl 7 &>/dev/null &>/dev/null &
TCP_PID=$!
ip netns exec WAN ncat -l 7 --keep-open --udp --exec "/bin/cat" &>/dev/null &
UDP_PID=$!
#ip netns exec WAN ncat -l 8 --keep-open --udp --exec "/bin/cat" &>/dev/null &
#UDP2_PID=$!

#Test bed validation
ip netns exec RTR   ping -c 4 -i 0.1 -W 0.2 10.0.0.1    &>/dev/null && test_pass RTR-WAN   || test_fail RTR-WAN-1 & P1=$!
ip netns exec RTR   ping -c 4 -i 0.1 -W 0.2 10.0.1.1    &>/dev/null && test_pass RTR-WAN   || test_fail RTR-WAN-2 & P2=$!
ip netns exec HOST1 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST1-RTR || test_fail HOST1-RTR & P3=$!
ip netns exec HOST2 ping -c 4 -i 0.1 -W 0.2 192.168.0.1 &>/dev/null && test_pass HOST2-RTR || test_fail HOST2-RTR & P4=$!
wait $P1 $P2 $P3 $P4

#timeout 5 ip netns exec RTR tcpdump -lvnpi wan icmp &
#timeout 5 ip netns exec RTR tcpdump -lvnpi wan tcp &
#timeout 8 ip netns exec RTR tcpdump -lvnnpi wan udp &
#timeout 8 ip netns exec WAN tcpdump -lvnpi rtr udp &
#timeout 8 ip netns exec HOST1 tcpdump -lvnpi rtr udp &
#timeout 5 ip netns exec RTR tcpdump -lvnpi host1 &
sleep 0.5s

#Loop testing
# TODO: Detect TCP FIN packet and clear/delete map entry or just set to zero
# Use BPF map to store active TCP sessions
# Outgoing key for TCP NAT is src-ip << 32 | tcp-src << 16 | tcp-dst
# Incoming key for TCP_NET is dst-ip << 32 | tcp-dst << 16 | tcp-src
# Value in map is the IP address for NAT translation

#ip netns exec RTR  ./bpf_compiler $COPT -i host1 -d ingress -p 100 -m /var/run/bpf/RTR 'match icmp; decl SRC 4; decl IP_SRC 8; get ip-src IP_SRC; set val SRC %IP_SRC; calc sub IP_SRC 1; set map IP_SRC %SRC %IP_SRC; calc sub SRC 2; calc lsh IP_SRC 4; set map IP_SRC %SRC %IP_SRC'
#ip netns exec RTR  ./bpf_compiler $COPT -i host1 -d ingress -p 101 'match icmp; decl IP_SRC 4; get ip-src IP_SRC; set-reg-loop 5; start-loop; dec-reg-loop; calc sub IP_SRC 1; loop-reg; set ip-src %IP_SRC'
ip netns exec RTR  ./bpfc $COPT -i host1 -d ingress -p 101 -m /var/run/bpf/RTR 'match icmp; decl LOOP 4; set val LOOP 4; decl IP_SRC 4; get ip-src IP_SRC; set-reg-loop 8; start-loop; dec-reg-loop 1; calc sub IP_SRC 1; calc sub LOOP 1; match val LOOP lt 3; set-reg-loop 0; end-match; loop-reg; set ip-src %IP_SRC; set map LOOP 0xFF %LOOP'

timeout 3 ip netns exec HOST1 ping -c 3 192.168.0.1
ip netns exec RTR ./bpfc $COPTS -m /var/run/bpf/RTR -r LOOP

#Test bed cleanup
{ kill -9 $TCP_PID && wait $TCP_PID; } &>/dev/null 
{ kill -9 $UDP_PID && wait $UDP_PID; } &>/dev/null

wait &>/dev/null

#ip netns exec RTR ./bpf_compiler $COPTS -m /var/run/bpf/RTR -r ICMP_NAT
#ip netns exec RTR ./bpf_compiler $COPTS -m /var/run/bpf/RTR -r TCP_NAT
#ip netns exec RTR ./bpf_compiler $COPTS -m /var/run/bpf/RTR -r UDP_NAT

umount /var/run/bpf/RTR

ip netns del RTR
ip netns del WAN
ip netns del HOST1
ip netns del HOST2
