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
ip netns add CE1
ip netns add CE2
ip netns add PE1
ip netns add H1
ip netns add H2

ip netns exec CE1 mkdir -p /var/run/bpf/CE1
ip netns exec CE2 mkdir -p /var/run/bpf/CE2
ip netns exec H1 mkdir -p /var/run/bpf/H1
mount -t bpf bpffs /var/run/bpf/CE1
mount -t bpf bpffs /var/run/bpf/CE2
mount -t bpf bpffs /var/run/bpf/H1

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

ip -n CE1 link set h1 mtu 1800
ip -n CE2 link set h2 mtu 1800
ip -n CE1 link set pe1 mtu 1800
ip -n CE2 link set pe1 mtu 1800
ip -n PE1 link set ce1 mtu 1800
ip -n PE1 link set ce2 mtu 1800

ip -n H1 link set ce1 mtu 1500
ip -n H2 link set ce2 mtu 1500

ip netns exec H1 ethtool -K ce1 tso off gro off
ip netns exec H2 ethtool -K ce2 tso off gro off
ip netns exec CE1 ethtool -K h1 tso off gro off
ip netns exec CE2 ethtool -K h2 tso off gro off

ip netns exec PE1 ethtool -K ce1 tso off gro off
ip netns exec PE1 ethtool -K ce2 tso off gro off

ip -n H1 link set ce1 qlen 10000
ip -n H2 link set ce2 qlen 10000
ip -n CE1 link set h1 qlen 10000
ip -n CE2 link set h2 qlen 10000

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

#ip netns exec CE1 mkdir -p /var/run/bpf/CE1
#mount -t bpf bpffs /var/run/bpf/CE1

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

ip netns exec H1 iptables -t mangle -A POSTROUTING -p tcp -m tcp -j CHECKSUM --checksum-fill
ip netns exec H2 iptables -t mangle -A POSTROUTING -p tcp -m tcp -j CHECKSUM --checksum-fill

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

function fragment_unrolled() {
MAX=$1
MAXL=$(( 14 + $MAX ))
IPMAX=$(( $MAX - 20 ))
IPMAX=$(( $IPMAX / 8 ))
IPMAX=$(( $IPMAX * 8 ))
MAXL=$(( 34 + $IPMAX ))
IPTOTL=$(( 20 + $IPMAX ))
LOOPS=$(( 3000 - 34 ))
LOOPS=$(( $LOOPS / $IPMAX ))
LOOPS=$(( $LOOPS + 1 ))
echo "
decl IPLEN 2;
decl FRAG 2;
get len LEN;
match ip;
        get ip-frag FRAG;
        calc bswap FRAG;
        #Match packets with DF bit set
        calc and FRAG 64;
        #Clear DF bit
        match val FRAG gt 0;
                set ip-frag 0;
                #Send back up the stack
                reclassify;
        #If we are here, then we have an IP packet without the DF bit set
        match val LEN gt $MAX;
		get skb-ifindex IDX;
		save-packet BACKUP_BUF %LEN;
                set val IPLEN %LEN;
                calc sub IPLEN 34;
                set len $MAXL;
                set ip-len $IPTOTL;"
OFF=34
IPOFF=0
echo $LOOPS > frag.debug
#UNROLL LOOP STARTS HERE
#for I in 1 2 3 4
for I in $( seq 1 $LOOPS )
do
	FRAG=$(( $IPOFF / 8 ))
	FRAG_MF=$(( $FRAG + 8192 ))
	echo "OFF: $OFF IP_OFF: $IPOFF FRAG: $FRAG" >> frag.debug
	OFF=$(( $OFF + $IPMAX ))
	IPOFF=$(( $IPOFF + $IPMAX ))
echo "
			match val LEN gt 0;
	                        set ip-frag $FRAG_MF;
			end-match;
                        clone %IDX egress;
			match val LEN lt $IPMAX;
				goto FRAG_DONE;
			end-match;
                        calc sub IPLEN $IPMAX;
                        calc sub LEN $IPMAX;
			load-packet BACKUP_BUF $IPMAX $OFF 34;
			match val IPLEN lt $IPMAX;
				set ip-frag $FRAG;
                                set len %LEN;
                                calc bswap IPLEN;
                                set ip-len %IPLEN;
				set val LEN 0;
                        end-match;"
#UNROLLED LOOP ENDS HERE
done
echo "
		label FRAG_DONE;
		drop;
        end-match;
end-match;
"
}

function fragment() {
MAX=$1
MAXL=$(( 14 + $MAX ))
IPMAX=$(( $MAX - 20 ))
echo "
decl IPLEN 2;
decl L2 2;
decl L3 2;
decl L4 2;
decl FRAG 2;
get len LEN;
get skb-ifindex IDX;
save-packet BACKUP_BUF %LEN;
load-packet BACKUP_BUF %LEN;
match ip;
	get ip-frag FRAG;
	calc bswap FRAG;
	#Match packets with DF bit set
	calc and FRAG 64;
	#Clear DF bit
	match val FRAG gt 0;
		set ip-frag 0;
		#Send back up the stack
		reclassify;
	#If we are here, then we have an IP packet without the DF bit set
	match val LEN gt $MAX;
		set val IPLEN %LEN;
		calc sub IPLEN 34;
		set len $MAXL;
		set ip-len $MAX;
		set val L3 0;
		set val L2 34;
		set val L4 34;
		calc add L4 $MAX;
		set-reg-loop 5000;
		start-loop;
			dec-reg-loop $MAX;	
			set val FRAG %L3;
			calc div FRAG 8;
			match val IPLEN gt $MAX;
				calc add FRAG 8192;
			end-match;
			calc bswap FRAG;
			set ip-frag %FRAG;
			clone %IDX egress;
			#Math for next packet;
			match val IPLEN le $MAX;
				goto FRAG_DONE;
			end-match;

			calc add L3 $IPMAX;
			calc add L2 $IPMAX;
			calc sub IPLEN $IPMAX;
			calc sub LEN $IPMAX;
			set val L4 %L2;
			calc add L4 $IPMAX;
			match val L4 gt %LEN;
				goto FRAG_DONE;
			end-match;
			calc add L4 34;
			match val L4 gt 9000;
				goto FRAG_DONE;
			end-match;
			match val IPLEN gt %LEN;
				goto FRAG_DONE;
			end-match;
			match val L2 gt %LEN;
				goto FRAG_DONE;
			end-match;
			match val IPLEN ge $IPMAX;
				set ip-tos 192;
				load-packet BACKUP_BUF $IPMAX %L2 34;
			end-match;
			#match val L4 le 9000;	
			#	load-packet BACKUP_BUF $MAX %L2 34;
			#end-match;
			match val IPLEN lt $IPMAX;
				#load-packet BACKUP_BUF %IPLEN %L2 34;
				set len %LEN;
				calc bswap IPLEN;
				set ip-len %IPLEN;
				calc bswap IPLEN;
			end-match;
		loop-reg;
		label FRAG_DONE;
	end-match;
end-match;
"
}

function mpls_out_nh()  {
TC=0
NH=$1
LABEL=$2
BOS=$3
TTL=$4
NH_LABEL=$5
echo "decl FIB_DMAC 8; 
decl MPLS1 4;
decl MPLS2 4;
fib-lookup $NH; 
match val %FIB_RESULT eq 0;
        #set skb-hash 0;
	#add-bytes 0 22;
	add-head-bytes 22;
	#get len LEN;
        #match val LEN gt 1436;
        #get map PKTS_OUT %LEN TOT;
        #calc add TOT 1;
        #set map PKTS_OUT %LEN %TOT;
        #end-match;
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
	#set skb-proto 0x8847;
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
        get bytes 18 8 DMAC;
        get bytes 24 8 SMAC;
        get bytes 30 2 ETHP;
        calc bswap %DMAC;
        calc bswap %SMAC;
        calc bswap %ETHP;
        #get len LEN;
        #decap-mpls;
        #set eth-proto 0x0800;
        #set bytes 14 1 0x45;
        #del-head-bytes 18;
        #set eth-proto 0x8847;
        #set bytes 14 1 0xff;
        #del-bytes 0 18;
	del-l2-bytes 18;
        set src-mac %SMAC;
        set dst-mac %DMAC;
        set eth-proto %ETHP;
        #recalc-*-csum doesn't work right now - throws verifier errors
        #match udp;
        #recalc-udp-csum;
        #end-match;
        #match tcp;
        #recalc-tcp-csum;
        #end-match;
        redirect $IFACE egress" | tr -d '\n' | tr -d '\t'
}

function mpls_in_slow()  {
LABEL=$1
IFACE=$2
echo "
	match mpls;
	match mpls-label $LABEL;
	#get len LEN;
	#match val LEN gt 1432;
	#get map PKTS_IN %LEN TOT;
	#calc add TOT 1;
	#set map PKTS_IN %LEN %TOT;
	#end-match;
	del-bytes 0 18;
	#get eth-proto ETHP;
	#set skb-proto %ETHP;
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

ip netns exec H1 ./bpf_compiler -v $COPTS -i ce1 -d egress -p 100 -m /var/run/bpf/H1 "$(fragment_unrolled 200)" && test_pass Fragment-install || (test_fail Fragment-install ; exit 1)
#exit 1
ip netns exec CE1 ./bpf_compiler $COPTS -i h1  -d ingress -p 100 -m /var/run/bpf/CE1 "$(mpls_out_nh 10.0.0.6 16 1 255 19)" && test_pass CE1-pw0-out-install || test_fail CE1-pw0-out-install
ip netns exec CE2 ./bpf_compiler $COPTS -i h2  -d ingress -p 100 -m /var/run/bpf/CE2 "$(mpls_out_nh 10.0.0.2 18 1 255 20)" && test_pass CE2-pw0-out-install || test_fail CE2-pw0-out-install
#ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 10 "match arp; accept"
#ip netns exec CE2 ./bpf_compiler $COPTS -i pe1 -d ingress -p 10 "match arp; accept"
ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 100 "$(mpls_in_slow 18 h1)" && test_pass CE1-pw0-in-install || test_fail CE1-pw0-in-install
#ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 101 "$(mpls_in_1 h1)" && test_pass CE1-pw0-in-install || test_fail CE1-pw0-in-install
ip netns exec CE2 ./bpf_compiler $COPTS -i pe1 -d ingress -p 100 "$(mpls_in_slow 16 h2)" && test_pass CE2-pw0-in-install || test_fail CE2-pw0-in-install
ip netns exec CE1 ./bpf_compiler $COPTS -i pe1 -d ingress -p 10 -m /var/run/bpf/CE1 "get mpls-label MPLS; set map MPLS %MPLS %MPLS"

#timeout 5 ip netns exec PE1 tcpdump -levnpi ce2 -XX &> out1.txt &
#timeout 5 ip netns exec CE1 tcpdump -levnpi pe1 -XX &
#timeout 5 ip netns exec CE2 tcpdump -levnpi pe1 -XX &
#timeout 5 ip netns exec CE1 tcpdump -levnpi h1 -XX &> out4.txt &
#timeout 5 ip netns exec CE1 tcpdump -levnpi h1 -XX &
#timeout 5 ip netns exec CE2 tcpdump -levnpi h2 -XX &
timeout 3 ip netns exec H1 tcpdump -levnpi ce1 -XX &
#timeout 10 ip netns exec H2 tcpdump -levnpi ce2 -XX &
sleep 0.5s

timeout 3 ip netns exec H1 ping -c1 -s 1800 -i 0.1 -W0.2 192.168.0.2 &>/dev/null && test_pass MPLS-pw || test_fail MPLS-pw

#cat out*.txt
#rm -f out*.txt

#timeout 10 ip netns exec H1 tcpdump -levnpi ce1 -XX &

if [ 1 -eq 0 ]
then
	ip netns exec CE1 $IPERF -s &>/dev/null & P1=$!
        ip netns exec CE2 $IPERF -s &>/dev/null & P2=$!
	sleep 1
        echo "TCP CE1->CE2"
        ip netns exec CE1 $IPERF -P 10 -i 5 -t 20 -c 10.0.0.6 | sed 's/^/  /g'
        echo "TCP CE2->CE1"
        ip netns exec CE2 $IPERF -P 10 -i 5 -t 20 -c 10.0.0.2 | sed 's/^/  /g'
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
fi

if [ 1 -eq 0 ]
then
	ip netns exec H2 $IPERF -s &>/dev/null & P1=$!
	ip netns exec H1 $IPERF -s &>/dev/null & P2=$!
	IDX=$(ip -n CE1 link show dev h1 | head -n1 | cut -f 1 -d :)
	#timeout 45 ip netns exec CE1 perf trace -e skb:kfree_skb --filter "skb_drop_reason(skb, $IDX)" &> CE1-h1-perf.log & P3=$!
	#ip netns exec H2 iperf3 -s & P1=$!
	#echo "start" | timeout 40 dropwatch -l kas &> dropwatch.log & P3=$!
	sleep 1
	echo "TCP H1->H2"
	ip netns exec H1 $IPERF -P 10 -i 5 -t 20 -c 192.168.0.2 | sed 's/^/  /g'
	echo "TCP H2->H1"
	ip netns exec H2 $IPERF -P 10 -i 5 -t 20 -c 192.168.0.1 | sed 's/^/  /g'
	#wait $P3
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
	#echo "Interface stats H1:"
        #ip netns exec H1 netstat -i | sed 's/^/  /g'
        #echo "Interface stats H2:"
        #ip netns exec H2 netstat -i | sed 's/^/  /g'

	#echo "Interface stats CE1:"
        #ip netns exec CE1 netstat -i | sed 's/^/  /g'
        #echo "Interface stats CE2:"
        #ip netns exec CE2 netstat -i | sed 's/^/  /g'

	#echo "CE1"
	#ip -s -d -n CE1 link show dev pe1
	#ip -s -d -n CE1 link show dev h1
	#ip netns exec CE1 ethtool -S pe1
	#ip netns exec CE1 ethtool -S h1
	#ip netns exec CE1 nstat -az | grep -iE 'drop|error|listen'
	#ip netns exec CE1 cat /proc/net/softnet_stat
	#ip netns exec CE1 bash -c 'for x in /sys/class/net/h1/statistics/*; do echo $x $(cat $x); done'
	#echo "CE2"
	#ip -s -d -n CE2 link show dev pe1
	#ip -s -d -n CE2 link show dev h2
	#ip netns exec CE2 nstat -az | grep -iE 'drop|error|listen'
	#ip netns exec CE2 cat /proc/net/softnet_stat
	#echo "TCP stats H1:"
	#ip netns exec H1 netstat -s -t | sed 's/^/  /g'
	#echo "TCP stats H2:"
	#ip netns exec H2 netstat -s -t | sed 's/^/  /g'
#ip netns exec CE1 ./bpf_compiler $COPTS -m /var/run/bpf/CE1 -r PKTS_OVR
#ip netns exec CE1 ./bpf_compiler $COPTS -m /var/run/bpf/CE1 -r PKTS_IN
#ip netns exec CE1 ./bpf_compiler $COPTS -m /var/run/bpf/CE1 -r PKTS_OUT
ip netns exec CE1 ./bpf_compiler $COPTS -m /var/run/bpf/CE1 -r MPLS

	#echo "TC filter CE1"
	#ip netns exec CE1 tc -s -d filter show dev pe1 ingress | sed 's/^/  /g'
	#echo "TC filter CE1"
	#ip netns exec CE2 tc -s -d filter show dev pe1 ingress | sed 's/^/  /g'
	#ip netns exec CE1 perf --no-pager script
fi

if [ 1 -eq 0 ]
then
	ip netns exec H2 $IPERF -u -s &>/dev/null & P1=$!
	ip netns exec H1 $IPERF -u -s &>/dev/null & P2=$!
	#ip netns exec H2 iperf3 -s & P1=$!
	sleep 1
	echo "UDP H1->H2"
	ip netns exec H1 $IPERF -u -i 5 -t 20 -c 192.168.0.2 -b 50g | sed 's/^/  /g'
	echo "UDP H2->H1"
	ip netns exec H2 $IPERF -u -i 5 -t 20 -c 192.168.0.1 -b 50g | sed 's/^/  /g'
	{ kill -9 $P1 $P2 && wait $P1 $P2; } &>/dev/null
fi


wait &>/dev/null
ip netns del H1
ip netns del H2
ip netns del PE1
ip netns del CE1
ip netns del CE2
