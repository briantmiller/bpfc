"""
Packet-level tests: scapy builds a packet, it is sent from ns_tx through a
bpfc program, and tcpdump captures what arrives in ns_rx.

    ns_tx: br0 -- veth_tx  <====>  veth_rx -- br0 :ns_rx

Programs on veth_tx egress are checked by capturing on veth_rx; programs on
veth_rx ingress by capturing on ns_rx's br0 (taps on veth_rx see packets
before the ingress program runs). Packets are sent raw, so the kernel needs
no IPv6 support for the IPv6 test.

    sudo python3 -m pytest -v tests/test_bpfc.py
"""
import os
import shutil
import subprocess
import tempfile

import pytest

scapy_all = pytest.importorskip("scapy.all")
from scapy.all import Ether, IP, IPv6, ICMP, ICMPv6EchoRequest, TCP, UDP, GRE, Dot1Q, rdpcap, wrpcap  # noqa: E402

if os.geteuid() != 0:
    pytest.skip("needs root", allow_module_level=True)
if not shutil.which("tcpdump"):
    pytest.skip("needs tcpdump", allow_module_level=True)

COMPILER_BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bpfc"))
NS_TX = "pyt_tx"
NS_RX = "pyt_rx"
VETH_TX = "pyt_vtx"
VETH_RX = "pyt_vrx"

state = {}


def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res.stdout


def ns_exec(ns, cmd, check=True):
    return run_cmd(f"ip netns exec {ns} {cmd}", check=check)


def bpfc(ns, args):
    """Installs a program; fails the test if bpfc or the verifier rejects it."""
    return ns_exec(ns, f"{COMPILER_BIN} {args}")


@pytest.fixture(scope="module", autouse=True)
def topology():
    if not os.path.exists(COMPILER_BIN):
        pytest.fail(f"{COMPILER_BIN} not found; run make first")
    for ns in (NS_TX, NS_RX):
        run_cmd(f"ip netns del {ns}", check=False)
        run_cmd(f"ip netns add {ns}")
        # IPv6 chatter (router solicitations, MLD) would only add noise
        ns_exec(ns, "sysctl -qw net.ipv6.conf.all.disable_ipv6=1", check=False)
        ns_exec(ns, "sysctl -qw net.ipv6.conf.default.disable_ipv6=1", check=False)
        ns_exec(ns, "ip link set lo up")
    run_cmd(f"ip link add {VETH_TX} netns {NS_TX} type veth peer name {VETH_RX} netns {NS_RX}")
    for ns, veth, addr in ((NS_TX, VETH_TX, "10.0.0.1/24"), (NS_RX, VETH_RX, "10.0.0.2/24")):
        ns_exec(ns, "ip link add br0 type bridge")
        ns_exec(ns, "ip link set br0 multicast off")
        ns_exec(ns, f"ip link set {veth} master br0")
        ns_exec(ns, f"ip link set {veth} up")
        ns_exec(ns, "ip link set br0 up")
        ns_exec(ns, f"ip addr add {addr} dev br0")
    state["tx_mac"] = ns_exec(NS_TX, f"cat /sys/class/net/{VETH_TX}/address").strip()
    state["rx_mac"] = ns_exec(NS_RX, "cat /sys/class/net/br0/address").strip()
    state["dir"] = tempfile.mkdtemp(prefix="bpfc-pytest.")
    state["send"] = os.path.join(state["dir"], "send_pcap.py")
    with open(state["send"], "w") as f:
        f.write("import sys\nfrom scapy.all import rdpcap, sendp\n"
                "sendp(rdpcap(sys.argv[1]), iface=sys.argv[2], verbose=False)\n")
    yield
    for ns in (NS_TX, NS_RX):
        run_cmd(f"ip netns del {ns}", check=False)
    shutil.rmtree(state["dir"], ignore_errors=True)


@pytest.fixture(autouse=True)
def detach_programs():
    """Every test starts and ends with no programs attached."""
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -c", check=False)
    ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -c", check=False)
    yield
    ns_exec(NS_TX, f"{COMPILER_BIN} -i {VETH_TX} -c", check=False)
    ns_exec(NS_RX, f"{COMPILER_BIN} -i {VETH_RX} -c", check=False)


def send_and_capture(pkt, capture_filter="", iface=VETH_RX, timeout=3):
    """Sends pkt out of ns_tx's br0 and returns the first packet tcpdump sees on
    iface in ns_rx (matching capture_filter), or None."""
    pin = os.path.join(state["dir"], "in.pcap")
    pout = os.path.join(state["dir"], "out.pcap")
    wrpcap(pin, [pkt])
    if os.path.exists(pout):
        os.remove(pout)
    cmd = ["ip", "netns", "exec", NS_RX, "tcpdump", "-i", iface, "-n", "-U", "-c", "1", "-w", pout]
    if capture_filter:
        cmd.append(capture_filter)
    sniffer = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    sniffer.stderr.readline()          # "listening on ...": capture is running
    ns_exec(NS_TX, f"python3 {state['send']} {pin} br0")
    try:
        sniffer.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        sniffer.terminate()
        sniffer.wait()
    if not os.path.exists(pout) or os.path.getsize(pout) <= 24:   # pcap header only
        return None
    pkts = rdpcap(pout)
    return pkts[0] if pkts else None


def checksums_valid(p):
    """True if the IP and TCP/UDP checksums in p are what scapy computes."""
    ip = p[IP]
    rebuilt = IP(bytes(ip))
    del rebuilt.chksum
    if L4 := (TCP if ip.haslayer(TCP) else UDP if ip.haslayer(UDP) else None):
        del rebuilt[L4].chksum
    rebuilt = IP(bytes(rebuilt))
    ok = rebuilt.chksum == ip.chksum
    if L4:
        ok = ok and rebuilt[L4].chksum == ip[L4].chksum
    return ok


# =====================================================================
# Tests
# =====================================================================

def test_l2_mac_and_eth_proto():
    """match eth-proto, set dst-mac, set src-mac"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match eth-proto 0x0800; set dst-mac aa:bb:cc:dd:ee:ff; "
                f"set src-mac 11:22:33:44:55:66; continue'")
    pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt, "icmp")
    assert out is not None
    assert out[Ether].dst == "aa:bb:cc:dd:ee:ff"
    assert out[Ether].src == "11:22:33:44:55:66"


def test_l3_ip_cidr_and_l4_range():
    """match ip-src CIDR, match tcp-dst range, set ip-dst, set tcp-dst; checksums stay valid"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-src 192.168.1.0/24; match tcp-dst 80-90; "
                f"set ip-dst 10.9.8.7; set tcp-dst 9999'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="192.168.1.55", dst="10.0.0.2") / TCP(sport=1234, dport=85)
    out = send_and_capture(pkt, "tcp")
    assert out is not None
    assert out[IP].dst == "10.9.8.7"
    assert out[TCP].dport == 9999

    # outside the CIDR or the port range: unchanged
    for src, dport in (("192.168.2.55", 85), ("192.168.1.55", 91)):
        pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src=src, dst="10.0.0.2") / TCP(sport=1234, dport=dport)
        out = send_and_capture(pkt, "tcp")
        assert out is not None
        assert out[IP].dst == "10.0.0.2" and out[TCP].dport == dport


def test_set_ip_dst_keeps_l4_checksum():
    """set ip-dst must also fix the TCP checksum (its pseudo-header covers the addresses)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; set ip-dst 10.9.8.7'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="192.168.1.55", dst="10.0.0.2") / TCP(sport=1234, dport=85)
    out = send_and_capture(pkt, "tcp")
    assert out is not None and out[IP].dst == "10.9.8.7"
    assert checksums_valid(out), "TCP checksum not updated after set ip-dst"


def test_set_tcp_dst_keeps_checksum():
    """set tcp-dst keeps the TCP checksum valid"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; set tcp-dst 9999'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="192.168.1.55", dst="10.0.0.2") / TCP(sport=1234, dport=85)
    out = send_and_capture(pkt, "tcp")
    assert out is not None and out[TCP].dport == 9999
    assert checksums_valid(out)


def test_variables_and_math():
    """get udp-src, calc add, set udp-dst %VAR (variables are in host order)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; get udp-src MY_PORT; calc add MY_PORT 5; set udp-dst %MY_PORT'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(dst="10.0.0.2") / UDP(sport=1000, dport=2222)
    out = send_and_capture(pkt, "udp")
    assert out is not None
    assert out[UDP].dport == 1005


def test_vlan_push():
    """push-vlan with a priority"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-tos 20; set ip-dst 10.0.0.3; push-vlan 50 3; continue'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2", tos=20) / ICMP()
    out = send_and_capture(pkt, "vlan")
    assert out is not None and out.haslayer(Dot1Q)
    assert out[Dot1Q].vlan == 50
    assert out[Dot1Q].prio == 3
    assert out[IP].dst == "10.0.0.3"


def test_vlan_push_then_set_id():
    """set vlan-id on a tag pushed earlier in the same program"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-tos 20; push-vlan 50 3; set vlan-id 100; continue'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2", tos=20) / ICMP()
    out = send_and_capture(pkt, "vlan")
    assert out is not None and out.haslayer(Dot1Q)
    assert out[Dot1Q].vlan == 100
    assert out[Dot1Q].prio == 3


def test_gre_encap():
    """encap-gre keeps the inner packet"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp-dst 53; encap-gre ip-src 1.1.1.1 ip-dst 2.2.2.2 key 7777'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=53) / b"DNS_QUERY"
    out = send_and_capture(pkt, "ip proto gre")
    assert out is not None
    assert out[IP].src == "1.1.1.1"
    assert out[IP].dst == "2.2.2.2"
    assert out.haslayer(GRE)
    assert out[GRE].key == 7777
    inner = out[GRE].payload
    assert inner[IP].dst == "10.0.0.2"
    assert bytes(inner[UDP].payload) == b"DNS_QUERY"


def test_gre_decap_and_reclassify():
    """match gre-key, decap-gre, reclassify, then a second program sees the inner packet"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 200 'match icmp; encap-gre ip-src 1.1.1.1 ip-dst 2.2.2.2 key 100'")
    bpfc(NS_RX, f"-i {VETH_RX} -d ingress -p 100 'match gre-key 100; decap-gre; reclassify'")
    bpfc(NS_RX, f"-i {VETH_RX} -d ingress -p 200 'match icmp; match ip-dst 10.0.0.2; set ip-dst 10.0.0.99'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt, "icmp", iface="br0")
    assert out is not None
    assert not out.haslayer(GRE)
    assert out[IP].dst == "10.0.0.99"


def test_drop_action():
    """drop: matching packets never arrive, others do"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-src 10.0.0.77; drop'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.77", dst="10.0.0.2") / ICMP()
    assert send_and_capture(pkt, "icmp", timeout=2) is None
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.88", dst="10.0.0.2") / ICMP()
    assert send_and_capture(pkt, "icmp") is not None


def ipv6_packet():
    return Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IPv6(src="fe80::1", dst="2001:db8::2", tc=0) / ICMPv6EchoRequest()


def test_ipv6_set_constants():
    """match ip6, set ip6-tclass, set ip6-src <address>"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip6; set ip6-tclass 46; set ip6-src 2001:db8::9'")
    out = send_and_capture(ipv6_packet(), "ip6")
    assert out is not None
    assert out[IPv6].tc == 46
    assert out[IPv6].src == "2001:db8::9"


def test_ipv6_match_dst():
    """match ip6-dst <address> (/128)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip6-dst 2001:db8::2; set ip6-tclass 46'")
    out = send_and_capture(ipv6_packet(), "ip6")
    assert out is not None
    assert out[IPv6].tc == 46, "match ip6-dst did not match the packet's destination"


def test_ipv6_copy_address_through_variable():
    """get ip6-dst VAR; set ip6-src %VAR copies all 16 bytes"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip6; get ip6-dst MY_V6; set ip6-src %MY_V6'")
    out = send_and_capture(ipv6_packet(), "ip6")
    assert out is not None
    assert out[IPv6].src == "2001:db8::2"
