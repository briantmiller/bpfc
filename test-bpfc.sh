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

#echo "${TESTS[@]}"
#if test_enabled TEST 
#then
#	test_pass
#fi
#exit

#Setup network
ulimit -l unlimited
ip netns add TX
ip netns add RX
ip netns add RX2
ip netns add HOST1
ip -n TX link set lo up
ip -n RX link set lo up
ip -n RX2 link set lo up
ip -n HOST1 link set lo up
ip netns exec TX mkdir -p /var/run/bpf/TX
ip netns exec RX mkdir -p /var/run/bpf/RX
#unshare --mount --net=/var/run/netns/TX mount -t bpf bpffs /sys/fs/bpf
#unshare --mount --net=/var/run/netns/RX mount -t bpf bpffs /sys/fs/bpf
#ip netns exec TX bash -c "mount | grep /sys/fs/bpf | grep -q '^bpffs ' || (umount /sys/fs/bpf; mount -t bpf bpffs /sys/fs/bpf; mount | grep bpf)"
#ip netns exec RX bash -c "mount | grep /sys/fs/bpf | grep -q '^bpffs ' || (umount /sys/fs/bpf; mount -t bpf bpffs /sys/fs/bpf ; mount | grep bpf)"
#ip netns exec TX mount -t bpf bpffs /var/run/bpf/TX
mount -t bpf bpffs /var/run/bpf/TX
#ip netns exec RX mount -t bpf bpffs /var/run/bpf/RX
mount -t bpf bpffs /var/run/bpf/RX
ip link add tx0 type veth peer name rx0
ip link add rx1 netns RX type veth peer name rx1 netns RX2
ip link add tx1 netns HOST1 type veth peer name host1 netns TX
ip -n RX  link set rx1 up
ip -n RX2 link set rx1 up
ip -n RX2 link set rx1 promisc on
ip -n HOST1 link set tx1 up
ip -n TX link set host1 up
ip link set tx0 netns TX
ip link set rx0 netns RX
ip -n TX link set tx0 up
ip -n RX link set rx0 up
ip -n TX link add br0 type bridge
ip -n RX link add br0 type bridge
ip -n TX link set tx0 master br0
ip -n RX link set rx0 master br0
ip -n TX link set br0 up
ip -n RX link set br0 up
ip -n TX addr add 10.0.0.1/24 dev br0
ip -n RX addr add 10.0.0.2/24 dev br0
ip -n TX addr add 10.1.1.1/30 dev host1
ip -n HOST1 addr add 10.1.1.2/30 dev tx1
ip -n TX link add lo0 type dummy
ip -n RX link add lo0 type dummy
ip -n TX addr add 1.1.1.1/32 dev lo0
ip -n RX addr add 2.2.2.2/32 dev lo0
ip -n RX addr add 10.2.2.1/30 dev rx1
ip -n RX2 addr add 10.2.2.2/30 dev rx1
ip -n TX link set lo0 up
ip -n RX link set lo0 up
ip -n TX route add 2.2.2.2/32 via 10.0.0.2
ip -n TX route add default via 10.0.0.2
ip -n RX route add 1.1.1.1/32 via 10.0.0.1
ip -n RX route add 10.1.1.0/30 via 10.0.0.1
ip -n RX2 route add 10.0.0.0/24 via 10.2.2.1
ip -n RX2 route add 10.1.1.0/24 via 10.2.2.1
ip -n HOST1 route add default via 10.1.1.1

RX2_rx1_mac=$(ip netns exec RX2 bash -c 'cat /sys/class/net/rx1/address')

#Encapsulate only ICMP packets with GRE from TX namespace
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 100 'match icmp; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100' &
#Drop ICMP packets leaving TX if not GRE encapsulated
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 999 'match icmp; drop' &
#Drop IPv6 packets - can cause noise with the monitors if in debug mode
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 8 'match ip6; drop' &
#Decapsulate GRE packets on RX namespace
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; reclassify' &
wait

#Start monitors
timeout 8 ip netns exec RX nc -kl 7 &>/dev/null &
TCP_PID=$!
timeout 8 ip netns exec RX tcpdump -c 5 -lvnpi br0 -Q in icmp &>/dev/null && test_pass Decap || test_fail Decap &
timeout 8 ip netns exec TX tcpdump -c 1 -lvnpi tx0 -Q out ip proto gre &>/dev/null && test_pass Encap-Tx || test_fail Encap-Tx &
timeout 8 ip netns exec RX tcpdump -c 1 -lvnpi rx0 -Q in ip proto gre &>/dev/null && test_pass Encap-Rx || test_fail Encap-Rx &
[ $DEBUG -ne 0 ] && timeout 8 ip netns exec RX tcpdump -lvnpi rx0 -Q in &

[ $DEBUG -ne 0 ] && echo "TX:" && ip netns exec TX tc filter show dev tx0 egress
[ $DEBUG -ne 0 ] && echo "RX:" && ip netns exec RX tc filter show dev rx0 ingress

#Wait for monitors to start sniffing
sleep 0.5s

#Test ICMP over GRE tunnel
if [ $DEBUG -ne 0 ]
then 
	ip netns exec TX ping -c 5 -i 0.1 2.2.2.2 && test_pass PASS || test_fail Ping
else
	ip netns exec TX ping -c 5 -i 0.1 2.2.2.2 &>/dev/null && test_pass Ping || test_fail Ping
fi

#Test TCP echo
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 && echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 && test_pass Echo || test_fail Echo

#Test drop rule
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 99 'match tcp; match tcp-dst 7; drop'
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_fail TCP-drop || test_pass TCP-drop

#Test rewriting TCP destination port
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 90 'match tcp; get tcp-dst TDST; calc add TDST 8; set tcp-dst %TDST'
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 90 'match tcp; get tcp-dst TDST; calc sub TDST 8; set tcp-dst %TDST'
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Calc || test_fail Calc

#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 92 'match tcp; push-net-bytes 20'
#ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 92 'match tcp; pop-net-bytes 20'
#echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "Push-net-bytes PASS" || echo "Push-net-bytes FAIL"


#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 91 'match tcp; get tcp-dst TDST; calc lsh TDST 7; set map TEST TDST %TDST; set tcp-dst 777'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 91 -m /var/run/bpf/TX 'match tcp; match tcp-dst 7; get tcp-dst TDST; calc lsh TDST 2; set map TEST TDST %TDST; set tcp-dst 777'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 92 -m /var/run/bpf/TX 'match tcp; match tcp-dst 777; get map TEST TDST DST; calc rsh DST 2; set tcp-dst %DST'
#timeout 8 ip netns exec TX tcpdump -c 4 -lvnnpi tx0 tcp &
sleep 0.5s

echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Map || test_fail Map

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c

ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 101 'match arp; match arp-oper 1; match arp-tpa 10.0.0.30; set arp-oper 2; get arp-spa SPA; get arp-sha SHA; set arp-sha de:ad:be:ef:ca:fe; set arp-tha %SHA; set arp-tpa %SPA; set arp-spa 10.0.0.30; redirect rx0 egress'
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 102 'match icmp; match icmp-type 8; set icmp-type 0; match ip-dst 10.0.0.30; get ip-src IP_SRC; set ip-dst %IP_SRC; set ip-src 10.0.0.30; get dst-mac DMAC; get src-mac SMAC; set dst-mac %SMAC; set src-mac %DMAC; redirect rx0 egress'
#timeout 3 ip netns exec TX tcpdump -c3 -lvnnpi tx0 icmp &
#sleep 0.5s 
timeout 4 ip netns exec TX ping -c2 10.0.0.30 &>/dev/null && test_pass ICMP-Echo || test_fail ICMP-Echo
ip netns exec TX ip neigh show 10.0.0.30 dev br0 | grep -q "de:ad:be:ef:ca:fe" && test_pass ARP-reply || test_pass ARP-reply




ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -c
#ip -n TX neigh get 10.0.0.2 dev br0 | cut -f 5 -d ' ' 
ip netns exec TX ./bpf_compiler $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100; redirect-neigh br0'
#ip netns exec TX ./bpf_compiler $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100; redirect br0 egress'
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; match icmp; match ip-dst 2.2.2.2; match icmp-type 8; set icmp-type 0; get ip-src IP_SRC; set ip-dst %IP_SRC; set ip-src 2.2.2.2; redirect-neigh br0'
#ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; match icmp; match ip-dst 2.2.2.2; redirect br0 ingress'
#timeout 5 ip netns exec TX tcpdump -levnnpi tx0 icmp or ip proto gre &
#timeout 5 ip netns exec RX tcpdump -levnnpi rx0 icmp or ip proto gre &
#timeout 5 ip netns exec RX tcpdump -levnnpi br0 icmp or ip proto gre &
#sleep 0.5s
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Redirect-neigh || test_fail Redirect-neigh

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
ip netns exec TX ./bpf_compiler $COPTS -i host1 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -c
ip netns exec TX ./bpf_compiler $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; fib-lookup; match val FIB_RESULT eq 0; set src-mac %FIB_SMAC; set dst-mac %FIB_DMAC; redirect %FIB_IFINDEX egress'
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Fib-lookup || test_fail Fib-lookup

ip netns exec TX ./bpf_compiler $COPTS -i host1 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'match ip-dst 2.2.2.2; clone br0 ingress; set ip-dst 10.2.2.2; redirect-neigh rx1'
timeout 3 ip netns exec RX2 tcpdump -c 2 -levnnpi rx1 icmp &>/dev/null && test_pass Clone-1 || test_fail Clone-1 &
sleep 0.5s
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Clone-2 || test_fail Clone-2

if [ 0 -eq 1 ]
then
ip netns exec TX ip route get 2.2.2.2 || echo "Setup for FIB testing FAIL"
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 100 'match icmp; match ip-dst 2.2.2.2; set ip-dst 5.5.5.5; set dst-mac 01:23:45:67:89:fe; set src-mac 00:00:00:00:00:00; reclassify'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 100 'match icmp; match ip-tos 192; continue; match src-mac 00:00:00:00:00:00; continue ; match ip-dst 2.2.2.2; set dst-mac 01:23:45:67:89:fe; set src-mac 00:00:00:00:00:00; set ip-tos 192; continue'
#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 101 'match icmp; match ip-dst 5.5.5.5; set ip-dst 2.2.2.2; fib-lookup; set src-mac %FIB_SMAC; set dst-mac %FIB_DMAC'
#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 101 'match icmp; fib-lookup direct; set src-mac %FIB_SMAC; set dst-mac %FIB_DMAC'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 101 'match icmp; match src-mac 00:00:00:00:00:00; redirect-neigh tx0'
#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 101 'match icmp; match ip-dst 5.5.5.5; set ip-dst 2.2.2.2'
timeout 5 ip netns exec TX tcpdump -c4 -levnnpi tx0 icmp &
sleep 0.5s
timeout 5 ip netns exec TX ping -W 0.2 -c 5 -i 0.1 2.2.2.2 &>/dev/null && echo "FIB PASS" || echo "FIB FAIL"
fi

ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 250 "match icmp; set dst-mac $RX2_rx1_mac; redirect rx1 egress"
timeout 5 ip netns exec RX2 tcpdump -c 3 -lvnpi rx1 icmp &>/dev/null && test_pass Redirect || test_fail Redirect &
sleep 0.5
timeout 5 ip netns exec TX ping -W 0.2 -c 5 -i 0.1 10.2.2.2 &>/dev/null 

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
ip netns exec TX ./bpf_compiler $COPTS -i host1 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -c

#skb-cb will get cleared when going through br0, so we can't rely on that, but mark persists within the same namespace
ip netns exec TX ./bpf_compiler $COPTS -i host1 -d ingress -p 101 'match icmp; match ip-dst 2.2.2.2; set skb-mark 100'
#Before sending to the RX namespace, set the cb value since the mark will not persist across namespace changes
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 100 'match skb-mark 100; set skb-cb 0 100; continue; drop'
#Only allow ICMP packets that have been tagged from our peer with cb 0 = 100, otherwise drop
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'match icmp; match ip-dst 2.2.2.2; match skb-cb 0 100; continue; drop'
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Skb-mark-cb || test_fail Skb-mark-cb

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
ip netns exec TX ./bpf_compiler $COPTS -i host1 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -c

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 100 'match ip; add-l2-bytes 4; set bytes 14 4 0xdeadbeef; continue' && test_pass Add-l2-bytes-install || test_fail Add-l2-bytes-install
#ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'get bytes 14 2 L25_1; get bytes 16 2 L25_2; match val L25_1 eq 0xdead; match val L25_2 eq 0xbeef; del-l2-bytes 4' && test_pass Del-l2-bytes-install || test_fail Del-l2-bytes-install
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 100 'get bytes 14 4 L25; match val L25 eq 0xdeadbeef; del-l2-bytes 4' && test_pass Del-l2-bytes-install || test_fail Del-l2-bytes-install
#timeout 12 ip netns exec TX tcpdump -levnnpi tx0 -XX &
#sleep 0.5s
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Add/del-l2-bytes || test_fail Add/del-l2-bytes

ip netns exec TX ./bpf_compiler $COPTS -i tx0 -c
ip netns exec TX ./bpf_compiler $COPTS -i host1 -c
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -c

kill -9 $TCP_PID &>/dev/null 
wait &>/dev/null
ip netns del TX
ip netns del RX
ip netns del RX2
ip netns del HOST1
