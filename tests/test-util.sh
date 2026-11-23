#!/bin/bash

cd "$(dirname "$0")/.." || exit 1
source tests/lib.sh
require_root util
require_cmds util ping awk

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



#Test bed setup
ip netns add H1
ip netns add H2
for N in H1 H2
do
	ip -n $N link set lo up
done
ip link add h2 netns H1 type veth peer name h1 netns H2
ip -n H1 link set h2 up
ip -n H2 link set h1 up
ip -n H1 addr add 10.0.0.1/24 dev h2
ip -n H2 addr add 10.0.0.2/24 dev h1
for N in H1 H2
do
ip netns exec $N mkdir -p /var/run/bpf/$N
umount /var/run/bpf/$N &>/dev/null
mount -t bpf bpffs /var/run/bpf/$N
done

#Sanity tests
timeout 3 ip netns exec H1 ping -c 2 -W 1 10.0.0.2 &>/dev/null && test_pass "H1-H2" || test_fail "H1-H2"

START=$(cat /proc/uptime | awk '{print $1}' | cut -f 1 -d . )
#Install ebpf programs
ip netns exec H1 ./bpfc -i h2 -d egress -p 10 -m /var/run/bpf/H1 "get time TIME; set map TIME %TIME %TIME"
ip netns exec H1 ./bpfc -i h2 -d egress -p 11 -m /var/run/bpf/H1 "get random RAND; set map RAND %RAND %RAND"

#Test programs
timeout 3 ip netns exec H1 ping -c 2 -W 1 10.0.0.2 &>/dev/null
STOP=$(cat /proc/uptime | awk '{print $1}' | cut -f 1 -d . )

HEX_TIME=$(ip netns exec H1 ./bpfc -m /var/run/bpf/H1 -r TIME | grep "^\[0000\]" | cut -f 6 -d ' ')
DEC_TIME=$(printf "%d\n" $HEX_TIME)
DEC_TIME="${DEC_TIME::-9}"
#echo $START
#echo $DEC_TIME
#echo $STOP
[ $START -le $DEC_TIME ] && test_pass Time-1 || test_fail Time-1
[ $STOP  -ge $DEC_TIME ] && test_pass Time-2 || test_fail Time-2

timeout 5 ip netns exec H1 ping -c 30 -i 0.001 -W 1 10.0.0.2 &>/dev/null
#ip netns exec H1 ./bpfc -m /var/run/bpf/H1 -r RAND | grep "^\[0000\]" | cut -f 6 -d ' '
#This is a poor test for randomness, but sufficient for our usecase
RAND=$(ip netns exec H1 ./bpfc -m /var/run/bpf/H1 -r RAND | grep Value | cut -f 3 -d : | sed 's/ 0x00000000//g' | tr -d '\n')
PASS=1
for N in 0 1 2 3 4 5 6 7 8 9 a b c d e f
do
	#echo -n $N: 
	NUM=$(echo $RAND | tr -cd "$N" | wc -c)
	if [ $NUM -lt 4 ]
	then
		test_fail Random-$N
		PASS=0
	fi
done
[ $PASS -eq 1 ] && test_pass Random

# Attaching: a foreign filter at the priority, -I, -T, -D, -c
H1() { ip netns exec H1 "$@"; }
H1 tc filter add dev h2 egress prio 30 protocol ip bpf bytecode '1,6 0 0 4294967295,' 2>/dev/null
out=$(H1 ./bpfc -i h2 -d egress -p 30 "continue" 2>&1)
[[ "$out" == *"holds an incompatible filter (protocol 0x0800); replacing it non-atomically"* ]] &&
	H1 tc filter show dev h2 egress | grep -q "protocol all pref 30 bpf" && test_pass Attach-replaces-foreign-filter || test_fail Attach-replaces-foreign-filter
out=$(H1 ./bpfc -i h2 -d egress -p 31 -I -n util_info "continue" 2>&1)
[[ "$out" == *"BPFC_INFO id="*"prio=31"*"name=util_info"* ]] && test_pass Attach-info || test_fail Attach-info
out=$(H1 ./bpfc -i h2 -T "continue" 2>&1)
[[ "$out" == *"the kernel accepts the program (not attached)"* ]] && ! H1 tc filter show dev h2 ingress | grep -q bpf &&
	test_pass Check-only || test_fail Check-only
H1 ./bpfc -i h2 -d egress -p 31 -D && ! H1 tc filter show dev h2 egress | grep -q "pref 31 " &&
	H1 tc filter show dev h2 egress | grep -q "pref 30 " && test_pass Delete-one-priority || test_fail Delete-one-priority
H1 ./bpfc -i h2 -d egress -c && [ -z "$(H1 tc filter show dev h2 egress)" ] && test_pass Clear || test_fail Clear

#Cleanup
for N in H1 H2
do
	ip netns del $N
	umount /var/run/bpf/$N &>/dev/null
done

tests_exit
