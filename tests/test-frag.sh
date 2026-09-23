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
IPERF="iperf"
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
ip netns add R1
ip netns add R2
ip netns add R3
ip netns add H1
ip netns add H2

ip netns exec R1 mkdir -p /var/run/bpf/R1
ip netns exec R2 mkdir -p /var/run/bpf/R2
ip netns exec H1 mkdir -p /var/run/bpf/H1
ip netns exec H2 mkdir -p /var/run/bpf/H2
mount -t bpf bpffs /var/run/bpf/R1
mount -t bpf bpffs /var/run/bpf/R2
mount -t bpf bpffs /var/run/bpf/H1
mount -t bpf bpffs /var/run/bpf/H2

rm -f /var/run/bpf/R1/*
rm -f /var/run/bpf/R2/*
rm -f /var/run/bpf/H1/*
rm -f /var/run/bpf/H2/*

for N in R1 R2 R3 H1 H2
do
	ip -n $N link set lo up
	ip -6 -n $N addr flush dev lo
done

ip link add h1  netns R1 type veth peer name r1 netns H1
ip link add h2  netns R2 type veth peer name r2 netns H2
ip link add r3 netns R1 type veth peer name r1 netns R3
ip link add r3 netns R2 type veth peer name r2 netns R3

sleep 0.1s

ip -n R1 link set h1 mtu 3000
ip -n R2 link set h2 mtu 3000
ip -n R1 link set r3 mtu 1500
ip -n R2 link set r3 mtu 1500
ip -n R3 link set r1 mtu 1500
ip -n R3 link set r2 mtu 1500

ip -n H1 link set r1 mtu 3000
ip -n H2 link set r2 mtu 3000

ip netns exec H1 ethtool -K r1 tso off gro off
ip netns exec H2 ethtool -K r2 tso off gro off
ip netns exec R1 ethtool -K h1 tso off gro off
ip netns exec R2 ethtool -K h2 tso off gro off
ip netns exec R3 ethtool -K r1 tso off gro off
ip netns exec R3 ethtool -K r2 tso off gro off
ip netns exec R1 ethtool -K r3 tso off gro off
ip netns exec R2 ethtool -K r3 tso off gro off

#ip -n H1 link set r1 qlen 10000
#ip -n H2 link set r2 qlen 10000
#ip -n R1 link set h1 qlen 10000
#ip -n R2 link set h2 qlen 10000

ip -6 -n H1 addr flush dev r1
ip -6 -n H2 addr flush dev r2
ip -6 -n R1 addr flush dev h1
ip -6 -n R1 addr flush dev r3
ip -6 -n R2 addr flush dev h2
ip -6 -n R2 addr flush dev r3
ip -6 -n R3 addr flush dev r1
ip -6 -n R3 addr flush dev r2

ip -n H1 link set r1 up
ip -n H2 link set r2 up
ip -n R1 link set h1 up
ip -n R2 link set h2 up
ip -n R1 link set r3 up
ip -n R2 link set r3 up
ip -n R3 link set r1 up
ip -n R3 link set r2 up

ip -n H1 addr add 192.168.1.2/24 dev r1
ip -n H2 addr add 192.168.2.2/24 dev r2
ip -n R1 addr add 192.168.1.1/24 dev h1
ip -n R2 addr add 192.168.2.1/24 dev h2
ip -n R3 addr add 10.0.0.1/30    dev r1
ip -n R3 addr add 10.0.0.5/30    dev r2
ip -n R1 addr add 10.0.0.2/30    dev r3
ip -n R2 addr add 10.0.0.6/30    dev r3

ip -n R1 route add 10.0.0.4/30 via 10.0.0.1
ip -n R2 route add 10.0.0.0/30 via 10.0.0.5
ip -n R1 route add 192.168.2.0/24 via 10.0.0.1
ip -n R2 route add 192.168.1.0/24 via 10.0.0.5
ip -n R3 route add 192.168.1.0/24 via 10.0.0.2
ip -n R3 route add 192.168.2.0/24 via 10.0.0.6
ip -n H1 route add default via 192.168.1.1
ip -n H2 route add default via 192.168.2.1

ip -6 -n H1 addr flush dev r1
ip -6 -n H2 addr flush dev r2
ip -6 -n R1 addr flush dev h1
ip -6 -n R1 addr flush dev r3
ip -6 -n R2 addr flush dev h2
ip -6 -n R2 addr flush dev r3
ip -6 -n R3 addr flush dev r1
ip -6 -n R3 addr flush dev r2

ip netns exec H1 iptables -t mangle -A POSTROUTING -p tcp -m tcp -j CHECKSUM --checksum-fill
ip netns exec H2 iptables -t mangle -A POSTROUTING -p tcp -m tcp -j CHECKSUM --checksum-fill

if [ $DEBUG -eq 1 ]
then
	for N in R3 R1 R2
	do
		echo $N
		ip -br -c -n $N addr | sed 's/^/  /g'
		ip -n $N link
	done
fi

#Test bed validation
ip netns exec R1 ping -c 4 -i 0.1 -W 0.2 10.0.0.1 &>/dev/null && test_pass R1-R3 || test_fail R1-R3 & P1=$!
ip netns exec R2 ping -c 4 -i 0.1 -W 0.2 10.0.0.5 &>/dev/null && test_pass R2-R3 || test_fail R2-R3 & P1=$!
ip netns exec R1 ping -c 4 -i 0.1 -W 0.2 10.0.0.6 &>/dev/null && test_pass R1-R2 || test_fail R1-R2 & P3=$!
ip netns exec H1 ping -c 4 -i 0.1 -W 0.2 192.168.2.2 &>/dev/null && test_pass H1-H2 || test_fail H1-H2 & P4=$!
wait $P1 $P2 $P3 $P4

if [ 1 -eq 1 ]
then

ip netns exec R1 ./bpfc $COPTS -i h1 -d egress -p 100 -m /var/run/bpf/R1 "ip-defrag" && test_pass R1-defrag-install || test_fail R1-defrag-install
#ip netns exec R2 ./bpfc $COPTS -i h2 -d egress -p 100 -m /var/run/bpf/R2 "ip-defrag" && test_pass R2-defrag-install || test_fail R2-defrag-install

/bin/rm -f out*.txt
#timeout 5 ip netns exec R3 tcpdump -levnpi r2 -XX &> out1.txt &
#timeout 3 ip netns exec R1 tcpdump -levnpi r3 -XX icmp &>out1.txt & P1=$!
#timeout 5 ip netns exec R1 tcpdump -levnpi r3 -Q out -XX &
#timeout 3 ip netns exec R2 tcpdump -levnpi r3 -XX &
#timeout 5 ip netns exec R1 tcpdump -levnpi h1 -XX &> out4.txt &
#timeout 5 ip netns exec R1 tcpdump -levnpi h1 -XX icmp &> out.r1.txt &
#timeout 2 ip netns exec R2 tcpdump -c 2 -levnpi h2 -XX icmp &> out1.txt & P1=$!
#timeout 3 ip netns exec H1 tcpdump -levnpi r1 -XX icmp &> out.h1.txt &
#timeout 2 ip netns exec H1 tcpdump -c 1 -levnpi r1 -XX icmp &> out1.txt & P1=$!
#timeout 2 ip netns exec H1 tcpdump -c 1 -levnpi r1 -XX icmp &>out1.txt & P1=$!
#timeout 2 ip netns exec H2 tcpdump -c 3 -levnpi r2 -XX icmp &>out2.txt & P2=$!
#timeout 2 ip netns exec R2 tcpdump -c 2 -levnpi h2 -XX icmp &> out3.txt & P3=$!
sleep 0.5s

FRAG_SIZE=1100
ip netns exec R1 ./bpfc $COPTS -i h1 -d ingress -p 10 -m /var/run/bpf/R1 "ip-frag $FRAG_SIZE 3000" && test_pass R1-frag-$FRAG_SIZE-install || (test_fail R1-frag-$FRAG_SIZE-install ; exit 1)
ip netns exec R2 ./bpfc $COPTS -i h2 -d ingress -p 10 -m /var/run/bpf/R2 "ip-frag $FRAG_SIZE 3000" && test_pass R2-frag-$FRAG_SIZE-install || (test_fail R2-frag-$FRAG_SIZE-install ; exit 1)

#ip netns exec H1 ping -c 3 -s 2050 -i 0.1 -W 1 192.168.2.2

PING_PROC_NUM=100
PING_COUNT=100
PING_SIZE=2950

for FRAG_SIZE in 1450 1000 500 200
do
	MAX=$(( $FRAG_SIZE + 50 ))
	ip netns exec R1 ./bpfc $COPTS -i h1 -d ingress -p 10 -m /var/run/bpf/R1 "ip-frag $FRAG_SIZE 3000" && test_pass R1-frag-$FRAG_SIZE-install || (test_fail R1-frag-$FRAG_SIZE-install ; exit 1)
	ip netns exec R2 ./bpfc $COPTS -i h2 -d ingress -p 10 -m /var/run/bpf/R2 "ip-frag $FRAG_SIZE 3000" && test_pass R2-frag-$FRAG_SIZE-install || (test_fail R2-frag-$FRAG_SIZE-install ; exit 1)
	sleep 0.5s

	#ip netns exec H1 ping -c 3 -s $PING_SIZE -i 0.1 -W 1 192.168.2.2
	#ip netns exec H1 ping -c 3 -s 1578 -i 0.1 -W 1 192.168.2.2

	PPIDS=()
	for I in $( seq 1 $PING_PROC_NUM )
	do
		timeout 15 ip netns exec H1 ping -c $PING_COUNT -s $PING_SIZE -i 0.01 -W 2 192.168.2.2 &>/dev/null & 
		PPIDS+=($!)
	done

	PASS=1
	for PINGPID in "${PPIDS[@]}"
	do
		wait "$PINGPID" 
		RET=$?
		if [ $RET -ne 0 ]
		then
			PASS=0
			test_fail "IP-Frag-$PINGPID"
		fi
	done 
	[ $PASS -eq 1 ] && test_pass "IP-Frag-size-$FRAG_SIZE" || test_fail "IP-Frag-size-$FRAG_SIZE"
done
#wait $P1 $P2
#cat out*.txt
#rm -f out*.txt

#timeout 10 ip netns exec H1 tcpdump -levnpi r1 -XX &

FRAG_SIZE=1450
        ip netns exec R1 ./bpfc $COPTS -i h1 -d ingress -p 10 -m /var/run/bpf/R1 "ip-frag $FRAG_SIZE 3000" && test_pass R1-frag-$FRAG_SIZE-install || (test_fail R1-frag-$FRAG_SIZE-install ; exit 1)
        ip netns exec R2 ./bpfc $COPTS -i h2 -d ingress -p 10 -m /var/run/bpf/R2 "ip-frag $FRAG_SIZE 3000" && test_pass R2-frag-$FRAG_SIZE-install || (test_fail R2-frag-$FRAG_SIZE-install ; exit 1)


if [ 1 -eq 0 ]
then
	ip netns exec R1 $IPERF -s &>/dev/null & P1=$!
        ip netns exec R2 $IPERF -s &>/dev/null & P2=$!
	sleep 1
        echo "TCP R1->R2"
        ip netns exec R1 $IPERF -P 10 -i 5 -t 20 -c 10.0.0.6 | sed 's/^/  /g'
        echo "TCP R2->R1"
        ip netns exec R2 $IPERF -P 10 -i 5 -t 20 -c 10.0.0.2 | sed 's/^/  /g'
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
fi

if [ 1 -eq 1 ]
then
	PROCNUM=10
	ip netns exec H2 $IPERF -s &>/dev/null & P1=$!
	ip netns exec H1 $IPERF -s &>/dev/null & P2=$!
	IDX=$(ip -n R1 link show dev h1 | head -n1 | cut -f 1 -d :)
	#timeout 45 ip netns exec R1 perf trace -e skb:kfree_skb --filter "skb_drop_reason(skb, $IDX)" &> R1-h1-perf.log & P3=$!
	#ip netns exec H2 iperf3 -s & P1=$!
	#echo "start" | timeout 40 dropwatch -l kas &> dropwatch.log & P3=$!
	IPERF_OPTS="-m -P $PROCNUM -i 5 -t 5"
	$IPERF --help 2>&1 | grep -q "\--sum-only" && IPERF_OPTS="$IPERF_OPTS --sum-only"
	#timeout 2 ip netns exec R2 tcpdump -c 10 -levnpi h2 -XX tcp -Q out greater 600 &
	(for MSS in $(timeout 5 ip netns exec R2 tcpdump -c $PROCNUM -lvnpi h2 'tcp[tcpflags] & (tcp-syn) != 0' 2>/dev/null | grep mss | grep -oP 'mss\s+\K[0-9]+' | tr '\n' ' ')

	do
		[ $MSS -lt 2900 ] && test_fail TCP-MSS-$MSS
		export MSS=$MSS
	done ; [ $MSS -gt 2900 ] && test_pass TCP-MSS-$MSS ) &
	sleep 0.5s
	echo "TCP H1->H2"
	ip netns exec H1 $IPERF $IPERF_OPTS -c 192.168.2.2 | sed 's/^/  /g' | grep SUM | tail -n 1
	echo "TCP H2->H1"
	(for MSS in $(timeout 5 ip netns exec R2 tcpdump -c $PROCNUM -lvnpi h2 'tcp[tcpflags] & (tcp-syn) != 0' 2>/dev/null | grep mss | grep -oP 'mss\s+\K[0-9]+' | tr '\n' ' ')

        do
                [ $MSS -lt 2900 ] && test_fail TCP-MSS-$MSS
                export MSS=$MSS
        done ; [ $MSS -gt 2900 ] && test_pass TCP-MSS-$MSS ) &
	sleep 0.5s
	ip netns exec H2 $IPERF $IPERF_OPTS -c 192.168.1.2 | sed 's/^/  /g' | grep SUM | tail -n 1
	#wait $P3
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
	#echo "Interface stats H1:"
        #ip netns exec H1 netstat -i | sed 's/^/  /g'
        #echo "Interface stats H2:"
        #ip netns exec H2 netstat -i | sed 's/^/  /g'

	#echo "Interface stats R1:"
        #ip netns exec R1 netstat -i | sed 's/^/  /g'
        #echo "Interface stats R2:"
        #ip netns exec R2 netstat -i | sed 's/^/  /g'

	#echo "R1"
	#ip -s -d -n R1 link show dev r3
	#ip -s -d -n R1 link show dev h1
	#ip netns exec R1 ethtool -S r3
	#ip netns exec R1 ethtool -S h1
	#ip netns exec R1 nstat -az | grep -iE 'drop|error|listen'
	#ip netns exec R1 cat /proc/net/softnet_stat
	#ip netns exec R1 bash -c 'for x in /sys/class/net/h1/statistics/*; do echo $x $(cat $x); done'
	#echo "R2"
	#ip -s -d -n R2 link show dev r3
	#ip -s -d -n R2 link show dev h2
	#ip netns exec R2 nstat -az | grep -iE 'drop|error|listen'
	#ip netns exec R2 cat /proc/net/softnet_stat
	#echo "TCP stats H1:"
	#ip netns exec H1 netstat -s -t | sed 's/^/  /g'
	#echo "TCP stats H2:"
	#ip netns exec H2 netstat -s -t | sed 's/^/  /g'
	#ip netns exec R1 ./bpfc $COPTS -m /var/run/bpf/R1 -r PKTS_OVR
	#ip netns exec R1 ./bpfc $COPTS -m /var/run/bpf/R1 -r PKTS_IN
	#ip netns exec R1 ./bpfc $COPTS -m /var/run/bpf/R1 -r PKTS_OUT
	#ip netns exec R1 ./bpfc $COPTS -m /var/run/bpf/R1 -r MPLS

	#echo "TC filter R1"
	#ip netns exec R1 tc -s -d filter show dev r3 ingress | sed 's/^/  /g'
	#echo "TC filter R1"
	#ip netns exec R2 tc -s -d filter show dev r3 ingress | sed 's/^/  /g'
	#ip netns exec R1 perf --no-pager script
fi

if [ 1 -eq 0 ]
then
	ip netns exec H2 $IPERF -u -s &>/dev/null & P1=$!
	ip netns exec H1 $IPERF -u -s &>/dev/null & P2=$!
	#ip netns exec H2 iperf3 -s & P1=$!
	sleep 1
	echo "UDP H1->H2"
	ip netns exec H1 $IPERF -u -P 10 -i 5 -t 20 -c 192.168.2.2 -b 50g | sed 's/^/  /g' | grep SUM
	echo "UDP H2->H1"
	ip netns exec H2 $IPERF -u -P 10 -i 5 -t 20 -c 192.168.1.2 -b 50g | sed 's/^/  /g' | grep SUM
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
fi

fi

wait &>/dev/null
#ip netns exec R2 ./bpfc $COPTS -m /var/run/bpf/R2 -r DEFRAG
for C in H1 H2 H3 R1 R2 R3
do      
        umount /var/run/bpf/$C &>/dev/null
done
ip netns del H1
ip netns del H2
ip netns del R3
ip netns del R1
ip netns del R2
