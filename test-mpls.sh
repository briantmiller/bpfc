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
ip netns add CE1
ip netns add CE2
ip netns add PE1
ip netns add H1
ip netns add H2
for N in CE1 CE2 PE1 H1 H2
do
	ip -n $N link set lo up
	ip -6 -n $N addr flush dev lo
done

ip link add h1  netns CE1 type veth peer name ce1 netns H1
ip link add h2  netns CE2 type veth peer name ce2 netns H2
ip link add pe1 netns CE1 type veth peer name ce1 netns PE1
ip link add pe1 netns CE2 type veth peer name ce2 netns PE1

sleep 0.1s

ip -6 -n H1  addr flush dev ce1
ip -6 -n H2  addr flush dev ce2
ip -6 -n CE1 addr flush dev h1
ip -6 -n CE1 addr flush dev pe1
ip -6 -n CE2 addr flush dev h2
ip -6 -n CE2 addr flush dev pe1
ip -6 -n PE1 addr flush dev ce1
ip -6 -n PE1 addr flush dev ce2

ip -n H1  link set ce1 up
ip -n H2  link set ce2 up
ip -n CE1 link set h1  up
ip -n CE2 link set h2  up
ip -n CE1 link set pe1 up
ip -n CE2 link set pe1 up
ip -n PE1 link set ce1 up
ip -n PE1 link set ce2 up

ip -n H1  addr add 192.168.0.1/24 dev ce1
ip -n H2  addr add 192.168.0.2/24 dev ce2
ip -n PE1 addr add 10.0.0.1/30    dev ce1
ip -n PE1 addr add 10.0.0.5/30    dev ce2
ip -n CE1 addr add 10.0.0.2/30    dev pe1
ip -n CE1 addr add 10.255.255.255/32    dev h1
ip -n CE2 addr add 10.0.0.6/30    dev pe1

ip -n CE1 route add 10.0.0.4/30 via 10.0.0.1
ip -n CE2 route add 10.0.0.0/30 via 10.0.0.5

ip -6 -n H1  addr flush dev ce1
ip -6 -n H2  addr flush dev ce2
ip -6 -n CE1 addr flush dev h1
ip -6 -n CE1 addr flush dev pe1
ip -6 -n CE2 addr flush dev h2
ip -6 -n CE2 addr flush dev pe1
ip -6 -n PE1 addr flush dev ce1
ip -6 -n PE1 addr flush dev ce2

ip netns exec CE1 mkdir -p /var/run/bpf/CE1
mount -t bpf bpffs /var/run/bpf/CE1

ip netns exec PE1 sysctl -w net.mpls.platform_labels=1048575 &>/dev/null
ip netns exec CE1 sysctl -w net.mpls.platform_labels=1048575 &>/dev/null
ip netns exec CE2 sysctl -w net.mpls.platform_labels=1048575 &>/dev/null

ip netns exec PE1 sysctl -w net.mpls.conf.ce1.input=1 &>/dev/null
ip netns exec PE1 sysctl -w net.mpls.conf.ce2.input=1 &>/dev/null
ip netns exec CE1 sysctl -w net.mpls.conf.pe1.input=1 &>/dev/null
ip netns exec CE2 sysctl -w net.mpls.conf.pe1.input=1 &>/dev/null

#ip -f mpls -n PE1 route add 19 as 16 via inet 10.0.0.6 dev ce2
#ip -f mpls -n PE1 route add 20 as 18 via inet 10.0.0.2 dev ce1
ip -f mpls -n PE1 route add 19 via inet 10.0.0.6 dev ce2
ip -f mpls -n PE1 route add 20 via inet 10.0.0.2 dev ce1

ip -f mpls -n PE1 route show

#ip -n CE1 addr flush dev h1
#ip -6 -n CE1 addr show dev h1 | grep -q inet6 && test_fail IPv6 || test_pass IPv6

#ip netns exec H1  sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null 
#ip netns exec H2  sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null
#ip netns exec CE1 sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null
#ip netns exec CE2 sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null
#ip netns exec PE1 sysctl -w net.ipv6.conf.all.disable_ipv6=0 &>/dev/null

if [ $DEBUG -eq 1 ]
then
	for N in PE1 CE1 CE2
	do
		echo $N
		ip -br -c -n $N addr | sed 's/^/  /g'
		ip -n $N link
	done
fi

#Test bed validation
ip netns exec CE1 ping -c 4 -i 0.1 -W 0.2 10.0.0.1 &>/dev/null && test_pass CE1-PE1 || test_fail CE1-PE1 & P1=$!
ip netns exec CE2 ping -c 4 -i 0.1 -W 0.2 10.0.0.5 &>/dev/null && test_pass CE2-PE1 || test_fail CE2-PE1 & P1=$!
ip netns exec CE1 ping -c 4 -i 0.1 -W 0.2 10.0.0.6 &>/dev/null && test_pass CE1-CE2 || test_fail CE1-CE2 & P3=$!
wait $P1 $P2 $P3

NH=10.0.0.6
LABEL=16
TC=0
BOS=0
TTL=255

#TODO: Account for next-hop label.
#  This would have another 4 bytes 
function mpls_out()  {
NH=$1
LABEL=$2
BOS=$3
TTL=$4
echo "decl FIB_DMAC 8; 
decl SMAC 8; 
decl DMAC 8;
decl MPLS 4;
fib-lookup $NH; 
match val %FIB_RESULT eq 0; 
	get eth-proto ETHP;
	get src-mac SMAC;
	get dst-mac DMAC;
	set val MPLS $LABEL;
	calc lsh MPLS 3;
	calc or MPLS $TC;
	calc lsh MPLS 1;
	calc or MPLS $BOS;
	calc lsh MPLS 8;
	calc or MPLS $TTL;
	calc bswap MPLS;
	add-l2-bytes 20;
	set bytes 14 4 %MPLS; 
	set bytes 18 8 %DMAC; 
	set bytes 24 8 %SMAC; 
	set bytes 30 2 %ETHP;
	set eth-proto 0x8847; 
	set dst-mac %FIB_DMAC; 
	set src-mac %FIB_SMAC;
	redirect %FIB_IFINDEX egress" | tr -d '\n' | tr -d '\t'
}

function mpls_out_nh()  {
TC=0
NH=$1
LABEL=$2
BOS=$3
TTL=$4
NH_LABEL=$5
echo "decl FIB_DMAC 8; 
#decl SMAC 8; 
#decl DMAC 8;
decl MPLS1 4;
decl MPLS2 4;
fib-lookup $NH; 
match val %FIB_RESULT eq 0; 
	add-bytes 0 22;
        #get eth-proto ETHP;
        #get src-mac SMAC;
        #get dst-mac DMAC;
	#add-head-bytes 22;
	#add-bytes 14 22;
	set val MPLS1 $NH_LABEL;
        calc lsh MPLS1 3;
        calc or MPLS1 $TC;
        calc lsh MPLS1 1;
        calc or MPLS1 0;
        calc lsh MPLS1 8;
        calc or MPLS1 $TTL;
        calc bswap MPLS1;
        set val MPLS2 $LABEL;
        calc lsh MPLS2 3;
        calc or MPLS2 $TC;
        calc lsh MPLS2 1;
        calc or MPLS2 $BOS;
        calc lsh MPLS2 8;
        calc or MPLS2 $TTL;
        calc bswap MPLS2;
	set bytes 14 4 %MPLS1;
        set bytes 18 4 %MPLS2; 
        set eth-proto 0x8847; 
        set dst-mac %FIB_DMAC; 
        set src-mac %FIB_SMAC;
        redirect %FIB_IFINDEX egress" | tr -d '\n' | tr -d '\t'
}

function mpls_in()  {
LABEL=$1
IFACE=$2
echo "
	match mpls;
	match mpls-label $LABEL;
	#decl DATA 8;
	#get bytes 18 8 DMAC;
	#get bytes 24 8 SMAC;
	#get bytes 30 2 ETHP;
	#calc bswap %DMAC;
	#calc bswap %SMAC;
	#calc bswap %ETHP;
	#get len LEN;
	#decap-mpls;
	#set eth-proto 0x0800;
	#set bytes 14 1 0x45;
	#del-head-bytes 18;
	#set eth-proto 0x8847;
	#set bytes 14 1 0xff;
	del-bytes 0 18;
	#set src-mac %SMAC;
	#set dst-mac %DMAC;
	#set eth-proto %ETHP;
        redirect $IFACE egress" | tr -d '\n' | tr -d '\t'
}

function mpls_in_1() {
IFACE=$1
echo "
	match skb-mark 100;
	del-head-bytes 18;
	set eth-proto 0x8847;
	redirect $IFACE egress
	" | tr -d '\n' | tr -d '\t' 
}

ip netns exec CE1 ./bpf_compiler $COPTS -i h1  -d ingress -p 100 "$(mpls_out_nh 10.0.0.6 16 1 255 19)" && test_pass CE1-pw0-out-install || test_fail CE1-pw0-out-install
ip netns exec CE2 ./bpf_compiler $COPTS -i h2  -d ingress -p 100 "$(mpls_out_nh 10.0.0.2 18 1 255 20)" && test_pass CE2-pw0-out-install || test_fail CE2-pw0-out-install
ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 10 "match arp; accept"
ip netns exec CE2 ./bpf_compiler $COPTS -i pe1 -d ingress -p 10 "match arp; accept"
ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 100 "$(mpls_in 18 h1)" && test_pass CE1-pw0-in-install || test_fail CE1-pw0-in-install
#ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 101 "$(mpls_in_1 h1)" && test_pass CE1-pw0-in-install || test_fail CE1-pw0-in-install
ip netns exec CE2 ./bpf_compiler $COPTS -i pe1 -d ingress -p 100 "$(mpls_in 16 h2)" && test_pass CE2-pw0-in-install || test_fail CE2-pw0-in-install


#timeout 5 ip netns exec PE1 tcpdump -levnpi ce2 -XX &> out1.txt &
#timeout 5 ip netns exec CE1 tcpdump -levnpi pe1 -XX &
#timeout 5 ip netns exec CE2 tcpdump -levnpi pe1 -XX &
#timeout 5 ip netns exec CE1 tcpdump -levnpi h1 -XX &> out4.txt &
#timeout 5 ip netns exec CE2 tcpdump -levnpi h2 -XX &
#timeout 5 ip netns exec H2 tcpdump -levnpi ce2 -XX &
#sleep 0.5s

timeout 5 ip netns exec H1 ping -c4 -i 0.1 -W0.2 192.168.0.2 &>/dev/null && test_pass MPLS-pw || test_fail MPLS-pw

#cat out*.txt
#rm -f out*.txt

#ip netns exec CE1 ./bpf_compiler $COPTS -m /var/run/bpf/CE1 -r FIB_RESULT

wait &>/dev/null
ip netns del H1
ip netns del H2
ip netns del PE1
ip netns del CE1
ip netns del CE2
