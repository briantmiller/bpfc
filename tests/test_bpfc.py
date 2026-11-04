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
from scapy.all import IPOption, Ether, IP, IPv6, ICMP, ICMPv6EchoRequest, TCP, UDP, GRE, Dot1Q, Dot1AD, ARP, Raw, rdpcap, wrpcap  # noqa: E402
from scapy.contrib.mpls import MPLS  # noqa: E402

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


def test_set_ip_src_keeps_udp_checksum():
    """set ip-src also fixes the UDP checksum"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; set ip-src 172.16.5.4'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000) / b"payload"
    out = send_and_capture(pkt, "udp")
    assert out is not None and out[IP].src == "172.16.5.4"
    assert checksums_valid(out), "UDP checksum not updated after set ip-src"


def test_set_ip_dst_leaves_udp_checksum_zero():
    """a UDP checksum of 0 means none and must stay 0"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; set ip-dst 10.9.8.7'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000, chksum=0) / b"payload"
    out = send_and_capture(pkt, "udp")
    assert out is not None and out[IP].dst == "10.9.8.7"
    assert out[UDP].chksum == 0


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


def test_vlan_set_id_from_variable():
    """get vlan-id, calc, set vlan-id %VAR keeps the priority"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-tos 20; push-vlan 100 5; get vlan-id V; calc add V 20; set vlan-id %V; continue'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2", tos=20) / ICMP()
    out = send_and_capture(pkt, "vlan")
    assert out is not None and out.haslayer(Dot1Q)
    assert out[Dot1Q].vlan == 120
    assert out[Dot1Q].prio == 5


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


def test_ipv6_match_against_variable():
    """match ip6-dst %VAR compares all four words: equal matches, different does not"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip6; get ip6-dst D; match ip6-dst %D; set ip6-tclass 46; "
                f"end-match; match ip6-src %D; set ip6-tclass 99'")
    out = send_and_capture(ipv6_packet(), "ip6")
    assert out is not None
    assert out[IPv6].tc == 46, "ip6-dst did not match itself through a variable"


def test_match_values_with_high_bit():
    """match ip-dst / src-mac where the 32-bit word has bit 31 set (10.0.0.200, aa:bb:cc:dd:..)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-dst 10.0.0.200; match src-mac aa:bb:cc:dd:ee:ff; set ip-tos 4'")
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.200") / ICMP()
    out = send_and_capture(pkt, "icmp")
    assert out is not None
    assert out[IP].tos == 4, "a match on a value with bit 31 set did not match"


def test_set_icmp_type_keeps_checksum():
    """set icmp-type keeps the ICMP checksum valid, also past 128 bytes"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match icmp; match icmp-type 8; set icmp-type 0'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8) / (b"x" * 500)
    out = send_and_capture(pkt, "icmp")
    assert out is not None and out[ICMP].type == 0
    rebuilt = ICMP(bytes(out[ICMP]))
    del rebuilt.chksum
    assert ICMP(bytes(rebuilt)).chksum == out[ICMP].chksum, "ICMP checksum wrong after set icmp-type"


def test_else_after_terminal_keeps_enclosing_match():
    """'drop; else; ...; end-if' inside a match: code after end-if is still inside the match"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; decl X 4; if val X eq 1; drop; else; set ip-tos 4; end-if; set ip-tos 8'")
    udp = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2", tos=0) / UDP(sport=1, dport=2)
    out = send_and_capture(udp, "udp")
    assert out is not None and out[IP].tos == 0, "the code after end-if ran outside 'match tcp'"
    tcp = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / IP(src="10.0.0.1", dst="10.0.0.2", tos=0) / TCP(sport=1, dport=2)
    out = send_and_capture(tcp, "tcp")
    assert out is not None and out[IP].tos == 8


# =====================================================================
# Less used commands, in the kernel
# =====================================================================

def eth():
    return Ether(src=state["tx_mac"], dst=state["rx_mac"])


def tos_of(out):
    return out[IP].tos if out is not None and out.haslayer(IP) else None


# ---- MPLS ----

def test_encap_mpls():
    """encap-mpls label 16 bos 1: an MPLS shim (TTL 64) between Ethernet and IP"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip; match icmp; encap-mpls label 16 bos 1'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), "mpls")
    assert out is not None and out[Ether].type == 0x8847
    assert out[MPLS].label == 16 and out[MPLS].s == 1 and out[MPLS].ttl == 64
    assert IP(bytes(out[MPLS].payload)).dst == "10.0.0.2"


def test_decap_mpls():
    """decap-mpls removes the label and makes the frame IPv4 again"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match mpls; decap-mpls'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"], type=0x8847) / MPLS(label=16, s=1, ttl=64) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt, "icmp")
    assert out is not None, "the decapsulated packet did not arrive as IPv4/ICMP"
    assert out[Ether].type == 0x0800 and not out.haslayer(MPLS)
    assert out[IP].dst == "10.0.0.2"


def mpls_packet(label=100, s=1, ttl=50):
    return Ether(src=state["tx_mac"], dst=state["rx_mac"], type=0x8847) / MPLS(label=label, s=s, ttl=ttl) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()


def test_mpls_label_match_and_set():
    """match mpls-label / mpls-bos, set mpls-label keeps bos and TTL"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match mpls; match mpls-label 100; match mpls-bos 1; set mpls-label 200'")
    out = send_and_capture(mpls_packet(), "mpls")
    assert out is not None and out.haslayer(MPLS)
    assert out[MPLS].label == 200 and out[MPLS].s == 1 and out[MPLS].ttl == 50


def test_mpls_label_through_variable():
    """get mpls-label, calc, set mpls-label %VAR; set mpls-bos"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match mpls; get mpls-label L; calc add L 1; set mpls-label %L; set mpls-bos 0'")
    out = send_and_capture(mpls_packet(label=100, s=1), "mpls")
    assert out is not None and out.haslayer(MPLS)
    assert out[MPLS].label == 101 and out[MPLS].s == 0 and out[MPLS].ttl == 50


# ---- QinQ, Ethernet ----

def test_push_qinq():
    """push-qinq 10 20 1 2: outer 802.1ad tag 10/prio 1, inner 802.1Q tag 20/prio 2"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip; match icmp; push-qinq 10 20 1 2; continue'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    assert out is not None and out.haslayer(Dot1AD) and out.haslayer(Dot1Q)
    assert out[Dot1AD].vlan == 10 and out[Dot1AD].prio == 1
    assert out[Dot1Q].vlan == 20 and out[Dot1Q].prio == 2
    assert out[IP].dst == "10.0.0.2"


def test_match_qinq():
    """match qinq: double-tagged frames only"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match qinq; drop'")
    qinq = Ether(src=state["tx_mac"], dst=state["rx_mac"]) / Dot1AD(vlan=10) / Dot1Q(vlan=20) / IP(dst="10.0.0.2") / ICMP()
    assert send_and_capture(qinq, "ether[12:2] = 0x88a8", timeout=2) is None
    assert send_and_capture(eth() / IP(dst="10.0.0.2") / ICMP(), "icmp") is not None


def test_match_qinq_block_closes():
    """end-match after match qinq closes its block (code after it runs for every packet)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match qinq; drop; end-match; match udp; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


def test_match_field_against_variable():
    """match <field> %VAR compares with the host-order value get stored"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; get ip-src S; get ip-len L; "
                f"match ip-src %S; match ip-len %L; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


def test_mpls_label_match_variable():
    """match mpls-label %VAR (masked, shifted field)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match mpls; decl L 4; set val L 100; match mpls-label %L; set mpls-label 300'")
    out = send_and_capture(mpls_packet(label=100), "mpls")
    assert out is not None and out[MPLS].label == 300


def test_match_queue_and_protocol_variable():
    """match queue, get protocol (host order)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; match queue 0; get protocol P; "
                f"decl E 4; set val E 2048; match val %P eq %E; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


def test_decap_mpls_ipv6():
    """decap-mpls sets EtherType 0x86DD when IPv6 follows the label"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match mpls; decap-mpls'")
    pkt = Ether(src=state["tx_mac"], dst=state["rx_mac"], type=0x8847) / MPLS(label=16, s=1, ttl=64) / IPv6(src="fd00::1", dst="fd00::2") / UDP(sport=1, dport=2)
    out = send_and_capture(pkt, "ip6")
    assert out is not None and out[Ether].type == 0x86DD and out[IPv6].dst == "fd00::2"


def test_push_eth():
    """push-eth: a new outer Ethernet header in front of the original frame"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip; match icmp; push-eth 02:00:00:00:00:aa 02:00:00:00:00:bb'")
    pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt)
    assert out is not None
    raw = bytes(out)
    assert raw[0:6] == bytes.fromhex("0200000000aa") and raw[6:12] == bytes.fromhex("0200000000bb")
    assert raw[14:14 + len(bytes(pkt))] == bytes(pkt), "the original frame does not follow the new header"


def test_push_eth_then_pop_eth():
    """pop-eth removes what push-eth added"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 100 'match ip; match icmp; push-eth 02:00:00:00:00:aa 02:00:00:00:00:bb'")
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 200 'pop-eth'")
    pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    out = send_and_capture(pkt, "icmp")
    assert out is not None and bytes(out)[:len(bytes(pkt))] == bytes(pkt)


# ---- ARP ----

def arp_request():
    return Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="02:00:00:00:00:01", psrc="10.0.0.200", pdst="10.0.0.2")


def test_arp_match_all_fields():
    """match arp-htype/ptype/hlen/plen/oper/sha/spa/tpa (all must match), then set arp-oper"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match arp; match arp-htype 1; match arp-ptype 0x0800; match arp-hlen 6; "
                f"match arp-plen 4; match arp-oper 1; match arp-sha 02:00:00:00:00:01; match arp-spa 10.0.0.200; "
                f"match arp-tpa 10.0.0.2; set arp-oper 2'")
    out = send_and_capture(arp_request(), "arp")
    assert out is not None and out[ARP].op == 2


def test_arp_set_fields():
    """set arp-sha/tha/spa/tpa and the header fields"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match arp; set arp-sha 02:00:00:00:00:99; set arp-tha 02:00:00:00:00:88; "
                f"set arp-spa 10.0.0.7; set arp-tpa 10.0.0.8; set arp-htype 6; set arp-ptype 0x0801; set arp-hlen 6; set arp-plen 4'")
    out = send_and_capture(arp_request(), "arp")
    assert out is not None
    a = bytes(out)[14:42]           # raw: scapy decodes the addresses by htype/ptype
    assert a[0:2] == b"\x00\x06" and a[2:4] == b"\x08\x01" and a[4] == 6 and a[5] == 4
    assert a[8:14] == bytes.fromhex("020000000099") and a[14:18] == bytes([10, 0, 0, 7])
    assert a[18:24] == bytes.fromhex("020000000088") and a[24:28] == bytes([10, 0, 0, 8])


def test_arp_get_fields():
    """get arp-spa/sha into variables and write them back swapped (sender <-> target)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match arp; get arp-spa SPA; get arp-tpa TPA; get arp-sha SHA; "
                f"get arp-oper OP; calc add OP 1; set arp-oper %OP; set arp-spa %TPA; set arp-tpa %SPA; set arp-tha %SHA'")
    out = send_and_capture(arp_request(), "arp")
    assert out is not None
    a = out[ARP]
    assert a.op == 2 and a.psrc == "10.0.0.2" and a.pdst == "10.0.0.200" and a.hwdst == "02:00:00:00:00:01"


# ---- other packet fields ----

def test_match_ip_proto_len_frag():
    """match ip-proto, ip-len, ip-frag (flags word), ip-frag-off"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match ip-proto 17; match ip-len 36; match ip-frag 0x4000; match ip-frag-off 0; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2", flags="DF") / UDP(sport=1, dport=2) / (b"x" * 8), "udp")
    assert tos_of(out) == 4
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2", flags="DF") / UDP(sport=1, dport=2) / (b"x" * 9), "udp")
    assert tos_of(out) == 0, "match ip-len matched a different length"


def test_get_tcp_win_and_offsets():
    """get tcp-win, l4-off and payload-off (IP and TCP options)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; get tcp-win W; set tcp-dst %W; get l4-off O; set ip-tos %O; "
                f"get payload-off P; set tcp-src %P'")
    pkt = eth() / opt_ip() / TCP(sport=1, dport=2, window=4321, options=[("NOP", None)] * 4)
    out = send_and_capture(pkt, "tcp")
    assert out is not None
    assert out[TCP].dport == 4321
    assert out[IP].tos == 14 + 24                  # IHL 6
    assert out[TCP].sport == 14 + 24 + 24          # TCP header 24 bytes with options


def test_gre_key_and_proto():
    """get gre-key, match gre-proto"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match gre; match gre-proto 0x0800; get gre-key K; set ip-tos %K'")
    pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / GRE(key_present=1, key=77, proto=0x0800) / IP(dst="1.2.3.4") / ICMP()
    out = send_and_capture(pkt, "ip proto gre")
    assert tos_of(out) == 77


def test_match_len_and_protocol():
    """match len (frame length) and match protocol (skb->protocol, IPv4 = 0x0800)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match protocol 0x0800; match len 60; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / (b"x" * 18), "udp")
    assert tos_of(out) == 4


# ---- metadata between programs on one hook ----

def test_skb_hash_and_queue_between_programs():
    """set skb-hash / queue in one program, match / get them in the next"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 100 'match udp; set skb-hash 4660; set queue 0'")
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 200 'match udp; match skb-hash 4660; get queue Q; calc add Q 4; set ip-tos %Q'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


def test_skb_ifindex_and_ingress():
    """match skb-ifindex is the interface the program runs on"""
    ifindex = int(ns_exec(NS_TX, f"cat /sys/class/net/{VETH_TX}/ifindex"))
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; match skb-ifindex {ifindex}; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


# ---- debug-log ----

def test_debug_log_reaches_trace_pipe():
    """debug-log writes its message to the trace buffer"""
    if not os.path.exists("/sys/kernel/tracing/trace"):
        subprocess.run("mount -t tracefs nodev /sys/kernel/tracing", shell=True, capture_output=True)
    trace = next((d for d in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing") if os.path.exists(d + "/trace")), None)
    if trace is None:
        pytest.skip("tracefs not mounted")
    with open(trace + "/trace", "w"):
        pass                                         # clear the buffer
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; debug-log bpfc-pytest-marker'")
    send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    with open(trace + "/trace") as f:
        assert "bpfc-pytest-marker" in f.read()


# ---- byte insertion and deletion ----

def test_del_bytes_middle():
    """del-bytes 42 4 removes 4 bytes after the UDP header, the rest moves up"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; del-bytes 42 4'")
    pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / b"AAAABBBBCCCC"
    out = send_and_capture(pkt, "udp")
    assert out is not None
    raw = bytes(out)
    assert len(raw) >= 50 and raw[42:50] == b"BBBBCCCC" and raw[:42] == bytes(pkt)[:42]


def test_add_bytes_middle():
    """add-bytes 42 4 inserts 4 zero bytes after the UDP header"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; add-bytes 42 4'")
    pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / b"AAAABBBB"
    out = send_and_capture(pkt, "udp")
    assert out is not None
    raw = bytes(out)
    assert raw[:42] == bytes(pkt)[:42] and raw[42:54] == b"\0\0\0\0AAAABBBB"


# ---- device type and kind (known while compiling, from -i) ----

def test_dev_kind_and_type_match():
    """match dev-kind / dev-type of the veth the program is compiled for"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; match dev-kind veth; match dev-type 1; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


def test_dev_kind_mismatch_takes_else():
    """if dev-kind gre on a veth: the else branch runs"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; if dev-kind gre; set ip-tos 1; else; set ip-tos 2; end-if'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 2


def test_ifkind_preprocessor_and_get_dev_type():
    """when $IFKIND == veth keeps the code; get dev-type into a variable"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; when $IFKIND == veth; get dev-type T; calc add T 9; set ip-tos %T; "
                f"otherwise; set ip-tos 3; end-when'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 10


# ---- IPv4 headers with options: L4 fields follow the real IHL ----

IPOPT4 = [IPOption(b"\x01\x01\x01\x01")]          # 4 bytes of NOP: IHL 6
IPOPT40 = [IPOption(b"\x01" * 40)]                 # IHL 15, the largest header


def opt_ip(opts=IPOPT4, **kw):
    return IP(src="10.0.0.1", dst="10.0.0.2", options=opts, **kw)


@pytest.mark.parametrize("opts", [IPOPT4, IPOPT40], ids=["ihl6", "ihl15"])
def test_ip_options_match_and_get_ports(opts):
    """match tcp-dst / port range / tcp-flags and get tcp-src with IP options"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; match tcp-dst 4321; match tcp-src 1000-2000; "
                f"match tcp-flags SYN; get tcp-src S; calc sub S 1200; set ip-tos %S'")
    out = send_and_capture(eth() / opt_ip(opts) / TCP(sport=1234, dport=4321, flags="S"), "tcp")
    assert out is not None and out[IP].ihl == 5 + sum(len(bytes(o)) for o in opts) // 4
    assert out[IP].tos == 34


def test_ip_options_no_false_match():
    """with options, the fixed offset used to read option bytes as the port"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match tcp; match tcp-dst 257; set ip-tos 4'")
    # bytes 36-37 (the old fixed tcp-dst) are 0x0101 = 257 here: option NOPs
    out = send_and_capture(eth() / opt_ip() / TCP(sport=1234, dport=80), "tcp")
    assert tos_of(out) == 0


def test_ip_options_set_ports_keeps_checksum():
    """set tcp-dst / udp-src with IP options: right bytes, valid L4 checksum"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 100 'match tcp; set tcp-dst 8080'")
    bpfc(NS_TX, f"-i {VETH_TX} -d egress -p 200 'match udp; set udp-src 5353'")
    out = send_and_capture(eth() / opt_ip() / TCP(sport=1234, dport=80) / b"hello", "tcp")
    assert out is not None and out[TCP].dport == 8080 and out[IP].ihl == 6 and checksums_valid(out)
    out = send_and_capture(eth() / opt_ip(IPOPT40) / UDP(sport=1, dport=2) / b"hello", "udp")
    assert out is not None and out[UDP].sport == 5353 and out[UDP].dport == 2 and checksums_valid(out)


def test_ip_options_icmp_type():
    """match / set icmp-type with IP options"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match icmp; match icmp-type 8; set icmp-type 13'")
    out = send_and_capture(eth() / opt_ip() / ICMP(type=8) / (b"x" * 40), "icmp")
    assert out is not None and out[ICMP].type == 13 and checksums_valid(out)


def test_ip_options_gre_key_and_checksum_bit():
    """get/match gre-key with IP options and with the GRE checksum bit set"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match gre; match gre-proto 0x0800; match gre-key 77; get gre-key K; set ip-tos %K'")
    for pkt in (eth() / opt_ip() / GRE(key_present=1, key=77, proto=0x0800) / IP(dst="1.2.3.4") / ICMP(),
                eth() / IP(src="10.0.0.1", dst="10.0.0.2") / GRE(chksum_present=1, key_present=1, key=77, proto=0x0800) / IP(dst="1.2.3.4") / ICMP()):
        out = send_and_capture(pkt, "ip proto gre")
        assert tos_of(out) == 77


def test_get_port_not_ipv4_is_zero():
    """get tcp-dst on a non-IPv4 frame stores 0 (like get tcp-seq)"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match arp; decl P 2; set val P 9; get tcp-dst P; set arp-oper %P'")
    out = send_and_capture(arp_request(), "arp")
    assert out is not None and out[ARP].op == 0


def test_match_protocol_variable():
    """match protocol %VAR against the host-order value get protocol stores"""
    bpfc(NS_TX, f"-i {VETH_TX} -d egress 'match udp; get protocol P; match protocol %P; set ip-tos 4'")
    out = send_and_capture(eth() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2), "udp")
    assert tos_of(out) == 4


# =====================================================================
# Devices without an Ethernet header (tun): the IP header is at offset 0
# =====================================================================

NS_TUN = "pyt_tun"
TUN = "pytun0"
CVE_PROG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dist", "examples", "cve-2026-98432.bpfc"))

# Runs in NS_TUN as the far end of the tun device: "udp DPORT [IPOPTS_HEX]"
# sends a UDP datagram out through the tun (its egress program runs); "raw HEX"
# writes an IP packet into it (its ingress program runs). Then every packet the
# kernel sends out through the tun within a second is printed as hex.
TUN_IO = r'''
import fcntl, os, select, socket, struct, sys, time
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", sys.argv[1].encode(), 0x0001 | 0x1000))  # TUNSETIFF, IFF_TUN|IFF_NO_PI
time.sleep(0.2)
if sys.argv[2] == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if len(sys.argv) > 4:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes.fromhex(sys.argv[4]))
    s.sendto(b"hello tun", ("10.9.0.2", int(sys.argv[3])))
else:
    os.write(fd, bytes.fromhex(sys.argv[3]))
end = time.time() + 1.0
while time.time() < end:
    r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
    if r:
        print(os.read(fd, 65535).hex(), flush=True)
'''


@pytest.fixture(scope="module")
def tun():
    run_cmd(f"ip netns del {NS_TUN}", check=False)
    run_cmd(f"ip netns add {NS_TUN}")
    ns_exec(NS_TUN, "ip link set lo up")
    ns_exec(NS_TUN, f"ip tuntap add dev {TUN} mode tun")
    ns_exec(NS_TUN, f"ip addr add 10.9.0.1/24 dev {TUN}")
    ns_exec(NS_TUN, f"ip link set {TUN} up")
    path = os.path.join(state["dir"], "tun_io.py")
    with open(path, "w") as f:
        f.write(TUN_IO)
    state["tun_io"] = path
    yield
    run_cmd(f"ip netns del {NS_TUN}", check=False)


def tun_io(*args):
    """The IPv4 packets the kernel sent out through the tun (scapy IP)."""
    out = ns_exec(NS_TUN, f"python3 {state['tun_io']} {TUN} " + " ".join(args))
    return [IP(bytes.fromhex(line)) for line in out.split() if line and line[0] == "4"]


def tun_bpfc(args):
    ns_exec(NS_TUN, f"{COMPILER_BIN} -i {TUN} -c", check=False)
    return ns_exec(NS_TUN, f"{COMPILER_BIN} -i {TUN} {args}")


def syn(dport, options=None):
    ip = IP(src="10.9.0.2", dst="10.9.0.1", options=options or [])
    return bytes(ip / TCP(sport=40000, dport=dport, flags="S")).hex()


def test_tun_constants(tun):
    """bpfc sees the tun's type and kind and puts the IP header at 0"""
    out = ns_exec(NS_TUN, f"{COMPILER_BIN} -i {TUN} -E 'debug-log $L3OFF $IFKIND $IFTYPE'")
    assert out.strip() == "debug-log 0 tun 65534;"


def test_tun_egress_fields(tun):
    """match ip / udp / udp-dst and set ip-tos / udp-dst at L3 offset 0"""
    tun_bpfc("-d egress 'match ip; match udp; match udp-dst 5000; set ip-tos 4; set udp-dst 6000'")
    pkts = [p for p in tun_io("udp", "5000") if p.haslayer(UDP)]
    assert pkts, "no UDP packet left the tun"
    p = pkts[0]
    assert p.tos == 4 and p[UDP].dport == 6000 and checksums_valid(p)


def test_tun_egress_ip_options(tun):
    """L4 fields at any IHL on a raw-IP device"""
    tun_bpfc("-d egress 'match udp; match udp-dst 5000; get l4-off O; set ip-tos %O'")
    pkts = [p for p in tun_io("udp", "5000", "01010100") if p.haslayer(UDP)]
    assert pkts and pkts[0].ihl == 6 and pkts[0].tos == 24


def test_tun_ingress_drop(tun):
    """match tcp / tcp-dst on ingress: the SYN to port 9 is dropped (no RST), port 10 is not"""
    tun_bpfc("-d ingress 'match tcp; match tcp-dst 9; drop'")
    assert not [p for p in tun_io("raw", syn(9)) if p.haslayer(TCP)]
    assert [p for p in tun_io("raw", syn(10)) if p.haslayer(TCP) and p[TCP].flags.R]


def test_tun_cve_example(tun):
    """the CVE-2026-98432 filter on a tun: a SYN with IP options is dropped, a plain one is not"""
    tun_bpfc(f"-d ingress -f {CVE_PROG}")
    opts = [IPOption(b"\x01\x01\x01\x00")]
    assert not [p for p in tun_io("raw", syn(9, opts)) if p.haslayer(TCP)]
    assert [p for p in tun_io("raw", syn(9)) if p.haslayer(TCP) and p[TCP].flags.R]


def test_tun_ethernet_field_refused(tun):
    """an Ethernet field on a tun is a compile error that names the problem"""
    res = subprocess.run(f"ip netns exec {NS_TUN} {COMPILER_BIN} -i {TUN} 'match ip; get src-mac M'",
                         shell=True, capture_output=True, text=True)
    assert res.returncode != 0 and "needs an Ethernet header" in res.stderr
