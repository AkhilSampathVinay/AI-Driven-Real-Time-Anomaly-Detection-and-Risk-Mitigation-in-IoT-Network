"""Tunable detection thresholds.

All rate thresholds use *packet timestamps* (not wall-clock time), so the same
logic works for live capture, PCAP replay and the synthetic demo.
"""

from dataclasses import dataclass, field


@dataclass
class Thresholds:
    # SYN flood: SYN-without-ACK packets from one source to one destination
    syn_flood_count: int = 100
    syn_flood_window: float = 5.0

    # UDP flood: UDP packets from one source to one destination
    udp_flood_count: int = 500
    udp_flood_window: float = 5.0

    # Port scan: distinct destination ports one source probes on one host
    vertical_scan_ports: int = 20
    # Horizontal scan: distinct hosts one source probes on the same port
    horizontal_scan_hosts: int = 15
    scan_window: float = 10.0

    # DNS tunneling: suspiciously long / random-looking DNS labels
    dns_label_max_len: int = 40
    dns_entropy_min: float = 3.5
    dns_query_rate_count: int = 100
    dns_query_rate_window: float = 5.0

    # Machine-learning (Isolation Forest) behaviour model
    ml_warmup_packets: int = 500
    ml_retrain_interval: float = 300.0
    ml_score_threshold: float = -0.15  # lower = more anomalous


@dataclass
class MiraiSignatures:
    telnet_ports: frozenset = frozenset({23, 2323})
    # Ports Mirai and its variants are known to target
    target_ports: frozenset = frozenset({23, 2323, 7547, 5555, 37215, 52869})
    # Byte patterns seen in Mirai brute-force / loader sessions
    payload_keywords: tuple = (
        b"/bin/busybox", b"enable\r\n", b"system\r\n", b"shell\r\n",
        b"sh\r\n", b"cd /tmp", b"wget http", b"tftp -g", b"chmod 777",
        b"mirai", b"ecchi",
    )
    # Default credentials from Mirai's hard-coded dictionary (subset)
    default_credentials: tuple = (
        b"xc3511", b"vizxv", b"admin\r\n", b"888888", b"xmhdipc",
        b"default", b"juantech", b"123456", b"54321", b"support",
        b"root\r\n", b"user\r\n", b"pass\r\n", b"7ujMko0admin",
    )
    # Exploit paths used by Mirai variants (TR-064 / Huawei HG532 / Realtek)
    exploit_paths: tuple = (b"/ctrlt/DeviceUpgrade_1", b"/picsdesc.xml", b"/UD/act?1")


@dataclass
class Config:
    thresholds: Thresholds = field(default_factory=Thresholds)
    mirai: MiraiSignatures = field(default_factory=MiraiSignatures)
