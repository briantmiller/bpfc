#!/bin/bash

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root bpfc
require_cmds bpfc ping nc tcpdump

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
ip netns exec TX mount -t bpf bpffs /var/run/bpf/TX
umount /var/run/bpf/TX &>/dev/null
mount -t bpf bpffs /var/run/bpf/TX
ip netns exec RX mount -t bpf bpffs /var/run/bpf/RX
umount /var/run/bpf/RX &>/dev/null
#mount -t bpf bpffs /var/run/bpf/RX
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
# Host addresses on each namespace's own lo (a dummy interface needs a kernel module some systems lack)
ip -n TX addr add 1.1.1.1/32 dev lo
ip -n RX addr add 2.2.2.2/32 dev lo
ip -n RX addr add 10.2.2.1/30 dev rx1
ip -n RX2 addr add 10.2.2.2/30 dev rx1
ip -n TX route add 2.2.2.2/32 via 10.0.0.2
ip -n TX route add default via 10.0.0.2
ip -n RX route add 1.1.1.1/32 via 10.0.0.1
ip -n RX route add 10.1.1.0/30 via 10.0.0.1
ip -n RX2 route add 10.0.0.0/24 via 10.2.2.1
ip -n RX2 route add 10.1.1.0/24 via 10.2.2.1
ip -n HOST1 route add default via 10.1.1.1

RX2_rx1_mac=$(ip netns exec RX2 bash -c 'cat /sys/class/net/rx1/address')
#Encapsulate only ICMP packets with GRE from TX namespace
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 100 'match icmp; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100' &
#Drop ICMP packets leaving TX if not GRE encapsulated
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 999 'match icmp; drop' &
#Drop IPv6 packets - can cause noise with the monitors if in debug mode
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 8 'match ip6; drop' &
#Decapsulate GRE packets on RX namespace
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; reclassify' &
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
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 99 'match tcp; match tcp-dst 7; drop'
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_fail TCP-drop || test_pass TCP-drop

#Test rewriting TCP destination port
#ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 90 'decl TDST 2;match tcp; get tcp-dst TDST; set tcp-dst %TDST'
#ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 90 'match tcp; get tcp-dst TDST; calc sub TDST 8; set tcp-dst %TDST'
#timeout 3 ip netns exec TX tcpdump -lvnnpi tx0 &
#timeout 3 ip netns exec RX tcpdump -lvnpi rx0 
#sleep 0.5s
#ip netns exec TX ping -c 1 2.2.2.2
#echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Get/Set tcp-dst || test_fail Get/Set tcp-dst

#Test rewriting TCP destination port
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 90 'match tcp; get tcp-dst TDST; calc add TDST 8; set tcp-dst %TDST'
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 90 'match tcp; get tcp-dst TDST; calc sub TDST 8; set tcp-dst %TDST'
#timeout 3 ip netns exec TX tcpdump -lvnnpi tx0 &
#timeout 3 ip netns exec RX tcpdump -lvnpi rx0 
#sleep 0.5s
#ip netns exec TX ping -c 1 2.2.2.2
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Calc || test_fail Calc

#ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 92 'match tcp; push-net-bytes 20'
#ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 92 'match tcp; pop-net-bytes 20'
#echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && echo "Push-net-bytes PASS" || echo "Push-net-bytes FAIL"


#ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 91 'match tcp; get tcp-dst TDST; calc lsh TDST 7; set map TEST TDST %TDST; set tcp-dst 777'
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 91 -m /var/run/bpf/TX 'match tcp; match tcp-dst 7; get tcp-dst TDST; calc lsh TDST 2; set map TEST TDST %TDST; set tcp-dst 777' || test_fail Map-install-1
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 92 -m /var/run/bpf/TX 'match tcp; match tcp-dst 777; get map TEST TDST DST; calc rsh DST 2; set tcp-dst %DST' || test_fail Map-install-2
#timeout 8 ip netns exec TX tcpdump -c 4 -lvnnpi tx0 tcp &
sleep 0.5s

echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Map || test_fail Map

ip netns exec TX ./bpfc $COPTS -i tx0 -c

ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 101 'match arp; match arp-oper 1; match arp-tpa 10.0.0.30; set arp-oper 2; get arp-spa SPA; get arp-sha SHA; set arp-sha de:ad:be:ef:ca:fe; set arp-tha %SHA; set arp-tpa %SPA; set arp-spa 10.0.0.30; redirect rx0 egress' || test_fail ICMP-Echo-Install-1
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 102 'match icmp; match icmp-type 8; set icmp-type 0; match ip-dst 10.0.0.30; get ip-src IP_SRC; set ip-dst %IP_SRC; set ip-src 10.0.0.30; get dst-mac DMAC; get src-mac SMAC; set dst-mac %SMAC; set src-mac %DMAC; redirect rx0 egress' || test_fail ICMP-Echo-Install-2
#timeout 3 ip netns exec TX tcpdump -c5 -levnnpi tx0 icmp & P1=$!
sleep 0.5s 
timeout 4 ip netns exec TX ping -c2 -i 0.1 -W 2 10.0.0.30 &>/dev/null && test_pass ICMP-Echo || test_fail ICMP-Echo
ip netns exec TX ip neigh show 10.0.0.30 dev br0 | grep -q "de:ad:be:ef:ca:fe" && test_pass ARP-reply || test_fail ARP-reply
#kill -9 $P1



ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c
#ip -n TX neigh get 10.0.0.2 dev br0 | cut -f 5 -d ' ' 
ip netns exec TX ./bpfc $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100; redirect-neigh br0'
#ip netns exec TX ./bpfc $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; encap-gre ip-src 10.0.0.1 ip-dst 10.0.0.2 key 100; redirect br0 egress'
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; match icmp; match ip-dst 2.2.2.2; match icmp-type 8; set icmp-type 0; get ip-src IP_SRC; set ip-dst %IP_SRC; set ip-src 2.2.2.2; redirect-neigh br0'
#ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 100 'match gre-key 100; decap-gre; match icmp; match ip-dst 2.2.2.2; redirect br0 ingress'
#timeout 5 ip netns exec TX tcpdump -levnnpi tx0 icmp or ip proto gre &
#timeout 5 ip netns exec RX tcpdump -levnnpi rx0 icmp or ip proto gre &
#timeout 5 ip netns exec RX tcpdump -levnnpi br0 icmp or ip proto gre &
#sleep 0.5s
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Redirect-neigh || test_fail Redirect-neigh

ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec TX ./bpfc $COPTS -i host1 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c
ip netns exec TX ./bpfc $COPTS -i host1 -d ingress -p 100 'match ip-dst 2.2.2.2; set dst-mac 0;'
ip netns exec TX ./bpfc $COPTS -i host1 -d ingress -p 101 'match ip-dst 2.2.2.2; get ip-dst IP_DST; fib-lookup %IP_DST; match val FIB_RESULT eq 0; set src-mac %FIB_SMAC; set dst-mac %FIB_DMAC; redirect %FIB_IFINDEX egress; '
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Fib-lookup || test_fail Fib-lookup

ip netns exec TX ./bpfc $COPTS -i host1 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 100 'match ip-dst 2.2.2.2; clone br0 ingress; set ip-dst 10.2.2.2; redirect-neigh rx1'
timeout 3 ip netns exec RX2 tcpdump -c 2 -levnnpi rx1 icmp &>/dev/null && test_pass Clone-1 || test_fail Clone-1 &
sleep 0.5s
ip netns exec HOST1 ping -c 3 2.2.2.2 &>/dev/null && test_pass Clone-2 || test_fail Clone-2

ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec TX ./bpfc $COPTS -i host1 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c

# Redirect: ICMP for 2.2.2.2 (RX's own address) would end at RX; the program
# sends it out rx1, so only with it does RX2 see packets for 2.2.2.2.
check Redirect-install ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 250 "match icmp; match ip-dst 2.2.2.2; set dst-mac $RX2_rx1_mac; redirect rx1 egress"
( timeout 4 ip netns exec RX2 tcpdump -c 3 -lnpi rx1 icmp and dst host 2.2.2.2 &>/dev/null && test_pass Redirect || test_fail Redirect ) &
SNIFF=$!
sleep 0.5
timeout 3 ip netns exec TX ping -W 0.2 -c 5 -i 0.1 2.2.2.2 &>/dev/null
wait $SNIFF
ip netns exec RX ./bpfc $COPTS -i rx0 -c

# skb-mark and skb-cb carry from one program to the next on the same hook (not
# between namespaces). Priority 101 drops ICMP for 2.2.2.2 unless priority 100
# marked it; without priority 100 the same ping must fail.
check Skb-mark-cb-install-1 ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 100 'match icmp; match ip-dst 2.2.2.2; set skb-mark 100; set skb-cb 0 77'
check Skb-mark-cb-install-2 ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 101 'match skb-mark 100; match skb-cb 0 77; continue; end-match; end-match; match icmp; match ip-dst 2.2.2.2; drop'
timeout 4 ip netns exec TX ping -c 3 -i 0.2 -W 1 2.2.2.2 &>/dev/null && test_pass Skb-mark-cb || test_fail Skb-mark-cb
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 100 -D
timeout 3 ip netns exec TX ping -c 2 -i 0.2 -W 1 2.2.2.2 &>/dev/null && test_fail Skb-mark-cb-unmarked-dropped || test_pass Skb-mark-cb-unmarked-dropped
ip netns exec TX ./bpfc $COPTS -i tx0 -c

# add-l2-bytes / del-l2-bytes: 4 bytes after the Ethernet header on the way
# out (marked 0xdeadbeef), removed again on the way in only if the marker is there.
check Add-l2-bytes-install ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 100 'match ip; add-l2-bytes 4; set bytes 14 4 0xdeadbeef; continue'
check Del-l2-bytes-install ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 100 'get bytes 14 4 L25; match val L25 eq 0xdeadbeef; del-l2-bytes 4'
timeout 4 ip netns exec TX ping -c 3 -i 0.2 -W 1 2.2.2.2 &>/dev/null && test_pass Add/del-l2-bytes || test_fail Add/del-l2-bytes

ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec TX ./bpfc $COPTS -i host1 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c

#ip netns exec RX tcpdump -levnnpi rx0 icmp & P1=$!
#sleep 0.5s

ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 100 'match ip-dst 2.2.2.2; push-vlan 100; accept' && test_pass VLAN push install || test_fail VLAN push install
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 104 'match vlan; match ip-dst 2.2.2.2; pop-vlan' && test_pass VLAN pop install || test_fail VLAN pop install
timeout 3 ip netns exec TX ping -c 3 -i 0.5 -W0.2 2.2.2.2 &>/dev/null && test_pass VLAN push/pop || test_fail VLAN push/pop

ip netns exec RX ./bpfc $COPTS -i rx0 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 101 'match vlan-id 100; pop-vlan' && test_pass VLAN match install || test_fail VLAN match install
timeout 3 ip netns exec TX ping -c 3 -i 0.5 -W0.2 2.2.2.2 &>/dev/null && test_pass VLAN match || test_fail VLAN match
ip netns exec RX ./bpfc $COPTS -i rx0 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 101 'match vlan-id 100-101; pop-vlan' && test_pass VLAN match range install || test_fail VLAN match range install
timeout 3 ip netns exec TX ping -c 3 -i 0.5 -W0.2 2.2.2.2 &>/dev/null && test_pass VLAN match range || test_fail VLAN match range

ip netns exec RX ./bpfc $COPTS -i rx0 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 101 'match vlan-id 100-101; get vlan-id VLAN; calc add VLAN 20; set vlan-id %VLAN' && test_pass VLAN change install 1 || test_fail VLAN change install 1
# Only VLAN 120-121 is let through (untagged or other ICMP is dropped), so the
# ping works only if set vlan-id really changed 100 to 120.
ip netns exec RX ./bpfc $COPTS -i rx0 -d ingress -p 105 'match vlan-id 120-121; pop-vlan; continue; end-match; match icmp; drop' && test_pass VLAN change install 2 || test_fail VLAN change install 2
timeout 3 ip netns exec TX ping -c 3 -i 0.5 -W0.2 2.2.2.2 &>/dev/null && test_pass VLAN change || test_fail VLAN change

ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c

# A variable declared after a free gets a zeroed slot: V2 must read 0, not
# V1's 4, or the destination port becomes 11 and the connection is refused.
timeout 6 ip netns exec RX nc -kl 7 &>/dev/null &
check Var-Free-install ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 90 'decl V1 4; set val V1 4; free V1; decl V2 2; match tcp; get tcp-dst TDST; calc add TDST %V2; set tcp-dst %TDST'
sleep 0.3
echo "ping " | timeout 4 ip netns exec TX nc -w 1 2.2.2.2 7 &>/dev/null && test_pass Var-Free || test_fail Var-Free


ip netns exec TX ./bpfc $COPTS -i tx0 -c
ip netns exec TX ./bpfc $COPTS -i host1 -c
ip netns exec RX ./bpfc $COPTS -i rx0 -c

#ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 10 'get ip-tos TOS; if TOS eq 192; set ip-tos 0; else; set ip-tos 8; end-if; match ip-tos 0; drop;'
#TODO: Fix else after a terminal 
ip netns exec TX ./bpfc $COPTS -i tx0 -d egress -p 10 'get ip-tos TOS; if val TOS eq 192; set ip-tos 0; else; set ip-tos 8; end-if; match ip-tos 0; drop; end-match;'

timeout 4 ip netns exec TX ping -c2 -i 0.1 -W 2 10.0.0.2 &>/dev/null && test_pass If-Else-1 || test_fail If-Else-1
timeout 4 ip netns exec TX ping -c2 -i 0.1 -W 2 -Q 192 10.0.0.2 &>/dev/null && test_fail If-Else-2 || test_pass If-Else-2

#ip netns exec TX ./bpfc $COPTS -m /var/run/bpf/RX -r VLAN
#ip netns exec TX ./bpfc $COPTS -m /var/run/bpf/RX -r OFF14
#kill -9 $P1

kill -9 $TCP_PID &>/dev/null 
wait &>/dev/null
for C in TX RX RX2 HOST1
do      
        umount /var/run/bpf/$C &>/dev/null
done
ip netns del TX
ip netns del RX
ip netns del RX2
ip netns del HOST1

tests_exit
