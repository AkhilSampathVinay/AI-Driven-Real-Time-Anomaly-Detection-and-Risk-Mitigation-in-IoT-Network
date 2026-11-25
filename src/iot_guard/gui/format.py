"""Text formatting of packets for the GUI and exports (no Tk dependency)."""

import textwrap
from datetime import datetime

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..detection import Severity, Verdict
from ..detection.rules import tcp_flags

try:
    from scapy.layers.http import HTTPRequest
except ImportError:  # pragma: no cover
    HTTPRequest = None


def clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def summary(pkt, verdict: Verdict) -> str:
    tag = "" if verdict.severity == Severity.NORMAL else f"[{verdict.severity.name}] "
    size = len(pkt)
    t = clock(float(pkt.time))
    if pkt.haslayer(DNSQR):
        body = f"DNS  {pkt[IP].src} → {pkt[DNSQR].qname.decode(errors='ignore')}"
    elif HTTPRequest is not None and pkt.haslayer(HTTPRequest):
        h = pkt[HTTPRequest]
        body = (f"HTTP {pkt[IP].src} → {(h.Host or b'').decode(errors='ignore')}"
                f"{(h.Path or b'').decode(errors='ignore')}")
    elif pkt.haslayer(TCP):
        flags = ",".join(tcp_flags(pkt[TCP].flags))
        body = (f"TCP  {pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport} "
                f"[{flags}]")
    elif pkt.haslayer(UDP):
        body = f"UDP  {pkt[IP].src}:{pkt[UDP].sport} → {pkt[IP].dst}:{pkt[UDP].dport}"
    else:
        body = pkt.summary()
    return f"{t}  {tag}{body}  ({size} B)"


def details(pkt, verdict: Verdict) -> str:
    out = ["=== Packet analysis ===",
           f"Captured : {datetime.fromtimestamp(float(pkt.time)):%Y-%m-%d %H:%M:%S.%f}"[:-3],
           f"Size     : {len(pkt)} bytes",
           f"Verdict  : {verdict.severity.name}"]
    for a in verdict.alerts:
        out.append(f"  - [{a.severity.name}] {a.category}: {a.message}")
    if verdict.severity == Severity.CRITICAL:
        out.append("  >> Recommended action: block the source IP (Mitigate…)")

    out.append("\n--- Protocol layers ---")
    if pkt.haslayer(Ether):
        e = pkt[Ether]
        out += ["[Ethernet]", f"  Source      : {e.src}", f"  Destination : {e.dst}",
                f"  Type        : 0x{e.type:04x}"]
    if pkt.haslayer(IP):
        ip = pkt[IP]
        out += ["[IPv4]", f"  Source      : {ip.src}", f"  Destination : {ip.dst}",
                f"  Protocol    : {ip.proto}", f"  TTL         : {ip.ttl}"]
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        out += ["[TCP]", f"  Ports       : {tcp.sport} → {tcp.dport}",
                f"  Flags       : {', '.join(tcp_flags(tcp.flags)) or 'none'}",
                f"  Seq         : {tcp.seq}"]
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        out += ["[UDP]", f"  Ports       : {udp.sport} → {udp.dport}"]
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        out += ["[DNS]", f"  Query       : {pkt[DNSQR].qname.decode(errors='ignore')}"]
    if HTTPRequest is not None and pkt.haslayer(HTTPRequest):
        h = pkt[HTTPRequest]
        out += ["[HTTP request]", f"  Method      : {(h.Method or b'').decode(errors='ignore')}",
                f"  Host        : {(h.Host or b'').decode(errors='ignore')}",
                f"  Path        : {(h.Path or b'').decode(errors='ignore')}"]
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
        out.append(f"[Payload] {len(data)} bytes")
        if data and printable / len(data) > 0.85:
            text = data[:1000].decode("utf-8", errors="replace").replace("\r", "")
            out.append(textwrap.indent(text, "  "))
        else:
            out.append(textwrap.indent(textwrap.fill(data[:128].hex(" "), 48), "  "))
    return "\n".join(out)
