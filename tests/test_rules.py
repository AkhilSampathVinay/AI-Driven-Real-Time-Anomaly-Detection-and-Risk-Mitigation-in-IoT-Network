import ipaddress

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from iot_guard.config import Config
from iot_guard.detection import Severity
from iot_guard.detection.rules import (
    DnsTunnelDetector,
    FloodDetector,
    MiraiDetector,
    ScanDetector,
    shannon_entropy,
)

CFG = Config()


def pkt(layer, t=0.0):
    p = Ether() / layer
    p.time = t
    return p


# ------------------------------------------------------------------ Mirai
def test_mirai_scanner_fingerprint_seq_equals_dst_ip():
    dst = "192.168.1.10"
    p = pkt(IP(src="192.168.1.66", dst=dst)
            / TCP(dport=23, flags="S", seq=int(ipaddress.IPv4Address(dst))))
    alert = MiraiDetector(CFG.mirai).check(p)
    assert alert and alert.severity == Severity.CRITICAL and "fingerprint" in alert.message


def test_normal_syn_to_telnet_is_not_mirai():
    p = pkt(IP(src="192.168.1.20", dst="192.168.1.10") / TCP(dport=23, flags="S", seq=12345))
    assert MiraiDetector(CFG.mirai).check(p) is None


def test_mirai_default_credentials_and_loader():
    det = MiraiDetector(CFG.mirai)
    cred = pkt(IP(src="10.0.0.9", dst="10.0.0.2") / TCP(dport=23, flags="PA") / Raw(b"xc3511\r\n"))
    loader = pkt(IP(src="10.0.0.9", dst="10.0.0.2") / TCP(dport=2323, flags="PA")
                 / Raw(b"/bin/busybox MIRAI\r\n"))
    assert det.check(cred).category == "mirai"
    assert det.check(loader).category == "mirai"


def test_regular_https_payload_is_not_mirai():
    """The original version flagged any payload containing words like 'login'."""
    p = pkt(IP(src="192.168.1.20", dst="52.1.1.1") / TCP(dport=443, flags="PA")
            / Raw(b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin"))
    assert MiraiDetector(CFG.mirai).check(p) is None


# ------------------------------------------------------------------ floods
def test_syn_flood_triggers_only_above_threshold():
    det = FloodDetector(CFG.thresholds)
    limit = CFG.thresholds.syn_flood_count
    alerts = [det.check(pkt(IP(src="1.2.3.4", dst="192.168.1.11") / TCP(sport=1000 + i,
                                                                         dport=80, flags="S"),
                            t=i * 0.01), i * 0.01) for i in range(limit + 5)]
    assert all(a is None for a in alerts[:limit])
    assert alerts[-1] is not None and alerts[-1].category == "syn_flood"


def test_slow_syns_never_trigger_flood():
    det = FloodDetector(CFG.thresholds)
    for i in range(500):  # 500 SYNs, but one per second -> sliding window never fills
        p = pkt(IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=443, flags="S"), t=float(i))
        assert det.check(p, float(i)) is None


def test_udp_flood():
    det = FloodDetector(CFG.thresholds)
    hits = [det.check(pkt(IP(src="192.168.1.66", dst="192.168.1.5") / UDP(dport=9999)),
                      i * 0.001) for i in range(CFG.thresholds.udp_flood_count + 1)]
    assert hits[-1] is not None and hits[-1].category == "udp_flood"


# ------------------------------------------------------------------ scans
def test_vertical_port_scan():
    det = ScanDetector(CFG.thresholds)
    res = [det.check(pkt(IP(src="192.168.1.66", dst="192.168.1.10")
                         / TCP(dport=port, flags="S")), port * 0.05) for port in range(1, 30)]
    assert any(r and r.category == "port_scan" for r in res)


def test_browsing_many_internet_hosts_is_not_a_scan():
    det = ScanDetector(CFG.thresholds)
    for i in range(50):
        p = pkt(IP(src="192.168.1.20", dst=f"93.184.{i}.10") / TCP(dport=443, flags="S"))
        assert det.check(p, i * 0.1) is None


def test_local_network_sweep_is_a_scan():
    det = ScanDetector(CFG.thresholds)
    res = [det.check(pkt(IP(src="192.168.1.66", dst=f"192.168.1.{i}")
                         / TCP(dport=23, flags="S")), i * 0.05) for i in range(2, 40)]
    assert any(r and "sweep" in r.message for r in res)


# ------------------------------------------------------------------ DNS
def test_dns_tunnel_high_entropy_label():
    det = DnsTunnelDetector(CFG.thresholds)
    q = "a9f3k2l1m0q8w7e6r5t4y3u2i1o0p9z8x7c6v5b4n3m2"
    p = pkt(IP(src="192.168.1.12", dst="192.168.1.1") / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{q}.exfil.net")))
    assert det.check(p, 0).category == "dns_tunnel"


def test_normal_dns_query():
    det = DnsTunnelDetector(CFG.thresholds)
    p = pkt(IP(src="192.168.1.12", dst="192.168.1.1") / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname="www.google.com")))
    assert det.check(p, 0) is None


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
