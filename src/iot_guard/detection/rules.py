"""Signature and rate-based detectors.

Each detector looks at one packet at a time and keeps whatever per-source
state it needs in sliding time windows. Windows are keyed on packet
timestamps so results are reproducible when replaying a PCAP.
"""

import ipaddress
import math
from collections import Counter, defaultdict, deque
from typing import Deque, Dict, Hashable, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from ..config import MiraiSignatures, Thresholds
from .verdict import Alert, Severity

# --------------------------------------------------------------------------- helpers

class SlidingCounter:
    """Counts events per key inside a moving time window."""

    def __init__(self, window: float):
        self.window = window
        self._events: Dict[Hashable, Deque[float]] = defaultdict(deque)

    def add(self, key: Hashable, ts: float) -> int:
        q = self._events[key]
        q.append(ts)
        while q and ts - q[0] > self.window:
            q.popleft()
        return len(q)

    def rate(self, key: Hashable) -> float:
        """Events per second over the span actually covered by the window."""
        q = self._events[key]
        span = q[-1] - q[0] if len(q) > 1 else 0.0
        return len(q) / max(span, 1e-3)


class SlidingDistinct:
    """Counts *distinct* values per key inside a moving time window."""

    def __init__(self, window: float):
        self.window = window
        self._events: Dict[Hashable, Deque[Tuple[float, Hashable]]] = defaultdict(deque)
        self._counts: Dict[Hashable, Counter] = defaultdict(Counter)

    def add(self, key: Hashable, value: Hashable, ts: float) -> int:
        q, c = self._events[key], self._counts[key]
        q.append((ts, value))
        c[value] += 1
        while q and ts - q[0][0] > self.window:
            _, old = q.popleft()
            c[old] -= 1
            if c[old] == 0:
                del c[old]
        return len(c)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def tcp_flags(flags) -> list:
    names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
    value = int(flags)
    return [names[i] for i in range(8) if value & (1 << i)]


def is_pure_syn(pkt) -> bool:
    flags = int(pkt[TCP].flags)
    return bool(flags & 0x02) and not flags & 0x10  # SYN set, ACK not set


# --------------------------------------------------------------------------- detectors

class MiraiDetector:
    """Detects the Mirai IoT botnet and its variants.

    1. Scanner fingerprint - Mirai's scanner sets the TCP sequence number equal
       to the destination IP address. This is a well-known, very low false
       positive indicator.
    2. Telnet brute force - default credentials / busybox commands sent to
       telnet ports.
    3. Loader / exploit payloads - wget/tftp droppers and known exploit URLs.
    """

    def __init__(self, sig: MiraiSignatures):
        self.sig = sig

    def check(self, pkt) -> Optional[Alert]:
        if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
            return None
        ip = pkt[IP]

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if is_pure_syn(pkt) and tcp.dport in self.sig.telnet_ports:
                if tcp.seq == int(ipaddress.IPv4Address(ip.dst)):
                    return Alert(Severity.CRITICAL, "mirai",
                                 f"Mirai scanner fingerprint (seq == dst IP) on port {tcp.dport}",
                                 ip.src, ip.dst)

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load).lower()
                if tcp.dport in self.sig.target_ports:
                    if any(k in payload for k in self.sig.payload_keywords):
                        return Alert(Severity.CRITICAL, "mirai",
                                     "Mirai loader command in telnet session", ip.src, ip.dst)
                    if tcp.dport in self.sig.telnet_ports and any(
                            payload.startswith(c.lower()) or payload == c.lower().strip()
                            for c in self.sig.default_credentials):
                        return Alert(Severity.CRITICAL, "mirai",
                                     "Mirai default-credential brute force on telnet",
                                     ip.src, ip.dst)
                if any(p.lower() in payload for p in self.sig.exploit_paths):
                    return Alert(Severity.CRITICAL, "mirai",
                                 "Known Mirai-variant exploit request", ip.src, ip.dst)

        elif pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load).lower()
            if b"/bin/busybox" in payload or (b"wget http" in payload and b"|sh" in payload):
                return Alert(Severity.CRITICAL, "mirai",
                             "Mirai-like command injection over UDP", ip.src, ip.dst)
        return None


class FloodDetector:
    """SYN flood and UDP flood detection with per-(src, dst) sliding windows."""

    def __init__(self, t: Thresholds):
        self.t = t
        self.syn = SlidingCounter(t.syn_flood_window)
        self.udp = SlidingCounter(t.udp_flood_window)

    def check(self, pkt, ts: float) -> Optional[Alert]:
        if not pkt.haslayer(IP):
            return None
        src, dst = pkt[IP].src, pkt[IP].dst

        if pkt.haslayer(TCP) and is_pure_syn(pkt):
            # Keyed on the target service port: a flood hammers one service,
            # whereas a port scan spreads SYNs across many ports.
            key = (src, dst, pkt[TCP].dport)
            n = self.syn.add(key, ts)
            if n > self.t.syn_flood_count:
                rate = self.syn.rate(key)
                return Alert(Severity.WARNING, "syn_flood",
                             f"SYN flood from {src} ({rate:.0f} SYN/s)", src, dst)

        elif pkt.haslayer(UDP) and not pkt.haslayer(DNS):
            n = self.udp.add((src, dst), ts)
            if n > self.t.udp_flood_count:
                rate = self.udp.rate((src, dst))
                return Alert(Severity.WARNING, "udp_flood",
                             f"UDP flood from {src} ({rate:.0f} pkt/s)", src, dst)
        return None


class ScanDetector:
    """Vertical (many ports, one host) and horizontal (one port, many hosts) scans."""

    def __init__(self, t: Thresholds):
        self.t = t
        self.vertical = SlidingDistinct(t.scan_window)
        self.horizontal = SlidingDistinct(t.scan_window)

    def check(self, pkt, ts: float) -> Optional[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and is_pure_syn(pkt)):
            return None
        src, dst, dport = pkt[IP].src, pkt[IP].dst, pkt[TCP].dport

        ports = self.vertical.add((src, dst), dport, ts)
        if ports > self.t.vertical_scan_ports:
            return Alert(Severity.WARNING, "port_scan",
                         f"Port scan from {src}: {ports} ports on {dst} in "
                         f"{self.t.scan_window:.0f}s", src, dst)

        # Horizontal sweeps only count inside the local network: a browser opening
        # connections to many internet hosts on :443 is normal, not a scan.
        if not ipaddress.ip_address(dst).is_private:
            return None
        hosts = self.horizontal.add((src, dport), dst, ts)
        if hosts > self.t.horizontal_scan_hosts:
            return Alert(Severity.WARNING, "port_scan",
                         f"Network sweep from {src}: {hosts} hosts on port {dport}", src, dst)
        return None


class DnsTunnelDetector:
    """Flags DNS queries that look like data exfiltration."""

    def __init__(self, t: Thresholds):
        self.t = t
        self.rate = SlidingCounter(t.dns_query_rate_window)

    def check(self, pkt, ts: float) -> Optional[Alert]:
        if not (pkt.haslayer(DNSQR) and pkt.haslayer(IP)) or pkt[DNS].qr != 0:
            return None
        src = pkt[IP].src
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        labels = qname.split(".")
        longest = max(labels, key=len) if labels else ""

        if (len(longest) > self.t.dns_label_max_len
                and shannon_entropy(longest) > self.t.dns_entropy_min):
            return Alert(Severity.WARNING, "dns_tunnel",
                         f"Possible DNS tunneling: high-entropy label ({len(longest)} chars)",
                         src, pkt[IP].dst)

        base = ".".join(labels[-2:])
        n = self.rate.add((src, base), ts)
        if n > self.t.dns_query_rate_count:
            return Alert(Severity.WARNING, "dns_tunnel",
                         f"Excessive DNS queries to {base} ({n} in "
                         f"{self.t.dns_query_rate_window:.0f}s)", src, pkt[IP].dst)
        return None
