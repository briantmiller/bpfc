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

timeout 5 ip netns exec H1 ping -c 20 -i 0.001 -W 1 10.0.0.2 &>/dev/null
#ip netns exec H1 ./bpfc -m /var/run/bpf/H1 -r RAND | grep "^\[0000\]" | cut -f 6 -d ' '
ip netns exec H1 ./bpfc -m /var/run/bpf/H1 -r RAND

#Cleanup
for N in H1 H2
do
	ip netns del $N
	umount /var/run/bpf/$N &>/dev/null
done
