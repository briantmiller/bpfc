#!/bin/bash

if [ $(whoami) != "root" ]
then
	echo "Must be run as root"
	exit 1
fi

DEBUG=0
while [ "$1" != "" ]
do
	ARG="$1"
	shift
	if [ "$ARG" == "-d" ]
	then
		DEBUG=1
	fi
done
COPTS=""
[ $DEBUG -eq 1 ] && COPTS=" -v "
#Setup network
ip netns add TX
ip netns add RX
ip netns add RX2
ip link add tx0 type veth peer name rx0
ip link add rx1 netns RX type veth peer name rx1 netns RX2
ip -n RX  link set rx1 up
ip -n RX2 link set rx1 up
ip -n RX2 link set rx1 promisc on
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
ip -n TX link add lo0 type dummy
ip -n RX link add lo0 type dummy
ip -n TX addr add 1.1.1.1/32 dev lo0
ip -n RX addr add 2.2.2.2/32 dev lo0
ip -n RX addr add 2.2.2.1/32 dev rx1
ip -n RX2 addr add 2.2.2.2/24 dev rx1
ip -n TX link set lo0 up
ip -n RX link set lo0 up
ip -n TX route add 2.2.2.2/32 via 10.0.0.2
ip -n RX route add 1.1.1.1/32 via 10.0.0.1
ip -n RX2 route add 10.0.0.0/24 via 2.2.2.1

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
timeout 8 ip netns exec RX tcpdump -c 5 -lvnpi br0 -Q in icmp &>/dev/null && echo Decap PASS || echo Decap FAIL &
timeout 8 ip netns exec TX tcpdump -c 1 -lvnpi tx0 -Q out ip proto gre &>/dev/null && echo Encap-Tx PASS || echo Encap-Tx FAIL &
timeout 8 ip netns exec RX tcpdump -c 1 -lvnpi rx0 -Q in ip proto gre &>/dev/null && echo Encap-Rx PASS || echo Encap-Rx FAIL &
[ $DEBUG -ne 0 ] && timeout 8 ip netns exec RX tcpdump -lvnpi rx0 -Q in &

[ $DEBUG -ne 0 ] && echo "TX:" && ip netns exec TX tc filter show dev tx0 egress
[ $DEBUG -ne 0 ] && echo "RX:" && ip netns exec RX tc filter show dev rx0 ingress

#Wait for monitors to start sniffing
sleep 0.5s

#Test ICMP over GRE tunnel
if [ $DEBUG -ne 0 ]
then 
	ip netns exec TX ping -c 5 -i 0.1 2.2.2.2 && echo "Ping PASS" || echo "Ping FAIL"
else
	ip netns exec TX ping -c 5 -i 0.1 2.2.2.2 &>/dev/null && echo "Ping PASS" || echo "Ping FAIL"
fi

#Test TCP echo
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 && echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 && echo "Echo PASS" || echo "Echo FAIL"

#Test drop rule
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 99 'match tcp; match tcp-dst 7; drop'
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "TCP drop FAIL" || echo "TCP drop PASS"

#Test rewriting TCP destination port
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 90 'match tcp; get tcp-dst TDST; calc add TDST 8; set tcp-dst %TDST'
ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 90 'match tcp; get tcp-dst TDST; calc sub TDST 8; set tcp-dst %TDST'
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "Calc PASS" || echo "Calc FAIL"

#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 92 'match tcp; push-net-bytes 20'
#ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 92 'match tcp; pop-net-bytes 20'
#echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "Push-net-bytes PASS" || echo "Push-net-bytes FAIL"


#ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 91 'match tcp; get tcp-dst TDST; calc lsh TDST 7; set map TEST TDST %TDST; set tcp-dst 777'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 91 'match tcp; get tcp-dst TDST; calc lsh TDST 7; set map TEST TDST 0xFFFFFFFFFFFFFFFF; set tcp-dst 777'
ip netns exec TX ./bpf_compiler $COPTS -i tx0 -d egress -p 92 'match tcp; match tcp-dst 777; get map TEST TDST DST; set tcp-dst %DST'
ls -lah /sys/fs/bpf/
timeout 5 ip netns exec RX tcpdump -c 3 -lvnnpi rx0 tcp &
timeout 5 ip netns exec TX tcpdump -c 3 -lvnnpi tx0 tcp &
sleep 0.5s
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "Map PASS" || echo "Map FAIL"

ip netns exec RX ./bpf_compiler $COPTS -i rx0 -d ingress -p 250 "match icmp; set dst-mac $RX2_rx1_mac; redirect rx1 egress"
sleep 0.5
timeout 5 ip netns exec RX2 tcpdump -c 3 -lvnpi rx1 icmp &>/dev/null && echo Redirect PASS || echo Redirect FAIL &
timeout 5 ip netns exec TX ping -W 0.2 -c 5 -i 0.1 2.2.2.2 &>/dev/null &

kill -9 $TCP_PID
wait &>/dev/null
ip netns del TX
ip netns del RX
ip netns del RX2
