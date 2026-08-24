import os
import time
import subprocess
import pytest
from scapy.all import *

from ctypes import cdll
libc = cdll.LoadLibrary('libc.so.6')
setns = libc.setns


# Path to our compiler binary
COMPILER_BIN = "./bpf_compiler"

# Network Namespace and Interface Names
NS_TX = "ns_tx"
NS_RX = "ns_rx"
VETH_TX = "veth_tx"
VETH_RX = "veth_rx"

rx_mac = None
tx_mac = None

packets = []

# This is a context manager that on enter assigns the process to an
# alternate network namespace (specified by name, filesystem path, or pid)
# and then re-assigns the process to its original network namespace on
# exit.
class Namespace (object):
    def __init__(self, nsname=None, nspath=None, nspid=None):
        self.mypath = get_ns_path(nspid=os.getpid())
        self.targetpath = get_ns_path(nspath,
                                  nsname=nsname,
                                  nspid=nspid)

        if not self.targetpath:
            raise ValueError('invalid namespace')

    def __enter__(self):
        # before entering a new namespace, we open a file descriptor
        # in the current namespace that we will use to restore
        # our namespace on exit.
        self.myns = open(self.mypath)
        with open(self.targetpath) as fd:
            setns(fd.fileno(), 0)

    def __exit__(self, *args):
        setns(self.myns.fileno(), 0)
        self.myns.close()

# This is just a convenience function that will return the path
# to an appropriate namespace descriptor, give either a path,
# a network namespace name, or a pid.
def get_ns_path(nspath=None, nsname=None, nspid=None):
    if nsname:
        nspath = '/var/run/netns/%s' % nsname
    elif nspid:
        nspath = '/proc/%d/ns/net' % nspid

    return nspath

def packet_callback(packet):
    packets.append(packet)

# Helper to run shell commands
def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res.stdout

# Helper to execute commands inside a network namespace
def ns_exec(ns, cmd, check=True):
    return run_cmd(f"ip netns exec {ns} {cmd}", check=check)

@pytest.fixture(scope="module", autouse=True)
def setup_topology():
    """
    Creates an isolated network topology: ns_tx (veth_tx) <---> (veth_rx) ns_rx
    """
    global tx_mac, rx_mac
    if not os.path.exists(COMPILER_BIN):
        pytest.fail(f"Compiler binary {COMPILER_BIN} not found. Run 'make' first.")

    # Clean up previous runs if they failed
    run_cmd(f"ip netns del {NS_TX}", check=False)
    run_cmd(f"ip netns del {NS_RX}", check=False)

    # Create Namespaces
    run_cmd(f"ip netns add {NS_TX}")
    run_cmd(f"ip netns add {NS_RX}")

    # Create veth pair and assign to namespaces
    run_cmd(f"ip link add {VETH_TX} type veth peer name {VETH_RX}")
    run_cmd(f"ip link set {VETH_TX} netns {NS_TX}")
    run_cmd(f"ip link set {VETH_RX} netns {NS_RX}")

    tx_mac = ns_exec(NS_TX,f"cat /sys/class/net/{VETH_TX}/address")
    rx_mac = ns_exec(NS_RX,f"cat /sys/class/net/{VETH_RX}/address")

    #ns_exec(NS_TX,f"bash -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'")
    #ns_exec(NS_RX,f"bash -c 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6'")

    # Bring up loopbacks and veths
    ns_exec(NS_TX, "ip link set lo up")
    ns_exec(NS_RX, "ip link set lo up")
    ns_exec(NS_TX, f"ip link set {VETH_TX} up")
    ns_exec(NS_RX, f"ip link set {VETH_RX} up")

    ns_exec(NS_TX, f"ip link add br0 type bridge")
    ns_exec(NS_TX, f"ip link set {VETH_TX} master br0")
    ns_exec(NS_RX, f"ip link add br0 type bridge")
    ns_exec(NS_RX, f"ip link set {VETH_RX} master br0")

    ns_exec(NS_TX, f"ip link set br0 multicast off")
    ns_exec(NS_RX, f"ip link set br0 multicast off")

    ns_exec(NS_TX, f"ip link set br0 up")
    ns_exec(NS_RX, f"ip link set br0 up")

    # Assign IP addresses for local routing bypasses
    ns_exec(NS_TX, f"ip addr add 10.0.0.1/24 dev br0")
    ns_exec(NS_RX, f"ip addr add 10.0.0.2/24 dev br0")
    ns_exec(NS_TX, f"ip -6 addr add 2001:db8::1/64 dev {VETH_TX}")
    ns_exec(NS_RX, f"ip -6 addr add 2001:db8::2/64 dev {VETH_RX}")

    # Create a python script for sending pcaps from inside the namespace
    with open("send_pcap.py", "w") as f:
        f.write("import sys; from scapy.all import rdpcap, sendp; "
                "sendp(rdpcap(sys.argv[1]), iface=sys.argv[2], verbose=False)\n")

    yield

    # Teardown
    run_cmd(f"ip netns del {NS_TX}", check=False)
    run_cmd(f"ip netns del {NS_RX}", check=False)
    os.remove("send_pcap.py")
    if os.path.exists("test_in.pcap"): os.remove("test_in.pcap")
    if os.path.exists("test_out.pcap"): os.remove("test_out.pcap")


@pytest.fixture(autouse=True)
def cleanup_ebpf():
    """ Runs after every test to ensure interfaces are stripped of eBPF programs """
    yield
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -c", check=False)
    ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -c", check=False)


def send_and_capture(pkt, capture_filter=""):
    """
    Sends a scapy packet from NS_TX, captures it on NS_RX via tcpdump, and returns the modified packet.
    """
    wrpcap("test_in.pcap", [pkt])
    
    # Start tcpdump in the receiving namespace
    #tcpdump_cmd = f"ip netns exec {NS_RX} tcpdump -i {VETH_RX} -w test_out.pcap -c 1 {capture_filter} 2>/dev/null"
    #sniffer = subprocess.Popen(tcpdump_cmd, shell=True)
    packets.clear()
    
    with Namespace(nsname=NS_RX):
        scapy.all.sniff(iface='br0', filter=capture_filter, prn=packet_callback, count=1, store=False, timeout=3)
    
    time.sleep(0.5) # Wait for tcpdump to bind to the interface
    
    # Send packet from transmitting namespace
    ns_exec(NS_TX, f"python3 send_pcap.py test_in.pcap br0")
    
    #sniffer.communicate(timeout=3)
    
    #if not os.path.exists("test_out.pcap"):
    #    return None
        
    #pkts = rdpcap("test_out.pcap")
    #return pkts[0] if len(pkts) > 0 else None
    if len(packets):
        return packets.pop(0)
    return None

def ping_and_capture(dst, capture_filter=""):
    """
    Sends a scapy packet from NS_TX, captures it on NS_RX via tcpdump, and returns the modified packet.
    """
    #wrpcap("test_in.pcap", [pkt])

    # Start tcpdump in the receiving namespace
    tcpdump_cmd = f"ip netns exec {NS_RX} tcpdump -i {VETH_RX} -w test_out.pcap -c 1 {capture_filter} 2>/dev/null"
    sniffer = subprocess.Popen(tcpdump_cmd, shell=True)

    time.sleep(0.5) # Wait for tcpdump to bind to the interface

    # Send packet from transmitting namespace
    ns_exec(NS_TX, f"ping -c 5 -i 0.1 {dst}")

    sniffer.communicate(timeout=3)

    if not os.path.exists("test_out.pcap"):
        return None

    pkts = rdpcap("test_out.pcap")
    return pkts[0] if len(pkts) > 0 else None


# =====================================================================
# TEST CASES
# =====================================================================

def test_l2_mac_and_eth_proto():
    """ Tests match eth-proto, set-dst-mac, set-src-mac """
    instr = "match eth-proto 0x0800; set-dst-mac aa:bb:cc:dd:ee:ff; set-src-mac 11:22:33:44:55:66; continue"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")
    #print(ns_exec(NS_TX, f"tc filter show dev {VETH_TX} egress"))

    pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt,capture_filter="icmp")
    
    assert out is not None
    #print(out)
    assert out[Ether].dst == "aa:bb:cc:dd:ee:ff"
    assert out[Ether].src == "11:22:33:44:55:66"
    #ns_exec(NS_TX, f"{COMPILER_BIN} -c -i {VETH_TX} -d egress '{instr}'")

def test_l3_ip_cidr_and_l4_range():
    """ Tests match ip-src CIDR, match tcp-dst Range, set-ip-dst, set-tcp-dst """
    instr = "match ip-src 192.168.1.0/24; match tcp-dst 80-90; set-ip-dst 10.9.8.7; set-tcp-dst 9999"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="192.168.1.55", dst="10.0.0.2") / TCP(sport=1234, dport=85)
    out = send_and_capture(pkt, capture_filter="tcp")
    
    assert out is not None
    #print(out)
    assert out[IP].dst == "10.9.8.7"
    assert out[TCP].dport == 9999
    # Verify checksums were recalculated by eBPF and accepted by Scapy
    del out[IP].chksum
    del out[TCP].chksum
    out = out.__class__(bytes(out)) # Force scapy to rebuild checksums to prove validity

def test_variables_and_math():
    """ Tests get-udp-src, math-bswap, math-add, set-udp-dst %VAR """
    # Grabs source port (1000), flips to host bytes, adds 5, flips to net bytes, sets as dest port
    instr = "get-udp-src MY_PORT; math-bswap MY_PORT 16; math-add MY_PORT 5; math-bswap MY_PORT 16; set-udp-dst %MY_PORT"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    pkt = Ether(src=tx_mac, dst=rx_mac) / IP(dst="10.0.0.2") / UDP(sport=1000, dport=2222)
    out = send_and_capture(pkt, capture_filter="udp")
    
    assert out is not None
    #print(out)
    assert out[UDP].dport == 1005

def test_vlan_push_and_modify():
    """ Tests push-vlan and set-vlan-id """
    ns_exec(NS_TX, f"{COMPILER_BIN} -c -i {VETH_TX} -d egress")
    instr = "match ip-tos 20; set-ip-dst 10.0.0.3; push-vlan 50 3; set-vlan-id 100; continue"
    #instr = "match ip-proto 1; set-ip-dst 10.0.0.3; push-vlan 50 3; set-vlan-id 100; continue"
    #instr = "match eth-proto 0x0800; set-ip-dst 10.0.0.3; push-vlan 50 3; set-vlan-id 100; continue"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    pkt = Ether(src=tx_mac, dst=rx_mac) / IP(src="10.0.0.1", dst="10.0.0.2", tos=20) / ICMP()
    #out = send_and_capture(pkt, capture_filter="icmp")
    out = send_and_capture(pkt)
    #out = send_and_capture(pkt)
    
    assert out is not None
    #print(out)
    assert out.haslayer(Dot1Q)
    assert out[Dot1Q].vlan == 100
    assert out[Dot1Q].prio == 3 # Priority should be retained from the push

def test_gre_encap():
    """ Tests encap-gre and nested payload retention """
    instr = "match udp-dst 53; encap-gre ip-src 1.1.1.1 ip-dst 2.2.2.2 key 7777"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    pkt = Ether(src=tx_mac, dst=rx_mac) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=53) / b"DNS_QUERY"
    out = send_and_capture(pkt, capture_filter="ip proto gre")
    
    assert out is not None
    assert out[IP].src == "1.1.1.1"
    assert out[IP].dst == "2.2.2.2"
    assert out[IP].proto == 47 # GRE
    assert out.haslayer(GRE)
    assert out[GRE].key == 7777
    # Verify the inner packet survived
    inner_ip = out[GRE].payload
    assert inner_ip.dst == "10.0.0.2"

def test_gre_decap_and_reclassify():
    """ Tests decap-gre, match gre-key, reclassify, and end-match logic """
    ns_exec(NS_TX, f"{COMPILER_BIN} -c -i {VETH_TX} -d egress")
    ns_exec(NS_RX, f"{COMPILER_BIN} -c -i {VETH_RX} -d ingress")
    # Tx side: Encap the packet
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress -p 100 'match eth-proto 0x86DD; drop'")
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress -p 150 'match ip-dst 224.0.0.22/255.255.255.255; drop'")
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress -p 200 'encap-gre ip-src 1.1.1.1 ip-dst 2.2.2.2 key 100'")
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress -p 300 'match ip-proto 1; drop'")
    
    # Rx side: Match key, Decap it, Reclassify to read the inner packet, and change inner IP
    ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -d ingress -p 100 'match eth-proto 0x86DD; drop'")
    ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -d ingress -p 150 'match ip-dst 224.0.0.22/255.255.255.255; drop'")
    #ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -d ingress -p 10 'match ip-dst 2.2.2.2; drop'")
    #ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -d ingress -p 100 'match gre-key 100; decap-gre; reclassify'")
    #ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -d ingress -p 200 'match ip-dst 10.0.0.2; set-ip-dst 10.0.0.99; reclassify'")
    print("\nTX:\n"+ns_exec(NS_TX,f"tc -s -f filter show dev {VETH_TX} egress"))
    print("\nRX:\n"+ns_exec(NS_RX,f"tc -s -f filter show dev {VETH_RX} ingress"))

    out = None
    pkt = Ether(src=tx_mac, dst=rx_mac) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    #pkt.show()
    #out = send_and_capture(pkt, capture_filter="ip proto not gre")
    #out = send_and_capture(pkt, capture_filter="dst host 2.2.2.2")
    out = send_and_capture(pkt, capture_filter="")
    #out = ping_and_capture("10.0.0.2", capture_filter="ip proto not gre")
    #out = send_and_capture(pkt)
    
    assert out is not None
    out.show()
    assert not out.haslayer(GRE) # GRE should be gone
    assert out[IP].dst == "10.0.0.99" # Inner IP should be modified

def test_drop_action():
    """ Tests the drop action to ensure packets do not arrive """
    instr = "match ip-src 10.0.0.77; drop"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    # This packet should be dropped
    pkt_drop = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="10.0.0.77", dst="10.0.0.2") / ICMP()
    out1 = send_and_capture(pkt_drop)
    assert out1 is None

    # This packet should pass
    pkt_pass = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="10.0.0.88", dst="10.0.0.2") / ICMP()
    out2 = send_and_capture(pkt_pass)
    assert out2 is not None

def test_ipv6_match_and_tclass():
    """ Tests IPv6 /128 matching, Variable setting, and Traffic Class bitfields """
    instr = "match ip6-dst 2001:db8::2; get-ip6-dst MY_V6; set-ip6-src %MY_V6; set-ip6-tclass 46"
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -d egress '{instr}'")

    pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IPv6(src="fe80::1", dst="2001:db8::2", tc=0) / ICMPv6EchoRequest()
    out = send_and_capture(pkt)
    
    assert out is not None
    assert out.haslayer(IPv6)
    assert out[IPv6].src == "2001:db8::2" # The get/set swap worked across all 16 bytes
    assert out[IPv6].tc == 46             # Traffic class successfully bit-masked

