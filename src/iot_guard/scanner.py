"""Local network discovery (ARP scan)."""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger(__name__)


@dataclass
class NetworkInfo:
    ssid: str = "Unknown"
    iface: Optional[str] = None
    my_ip: str = "127.0.0.1"
    gateway: Optional[str] = None
    subnet: str = "192.168.1.0/24"


@dataclass
class Device:
    ip: str
    mac: str
    name: str = ""
    vendor: str = ""
    tags: List[str] = field(default_factory=list)


def _ssid() -> str:
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"],
                                          timeout=5).decode(errors="ignore")
            m = re.search(r"^\s*SSID\s+:\s(.+)$", out, re.M)
            return m.group(1).strip() if m else "Unknown"
        if platform.system() == "Darwin":
            out = subprocess.check_output(["networksetup", "-getairportnetwork", "en0"],
                                          timeout=5).decode(errors="ignore")
            return out.split(":", 1)[-1].strip() or "Unknown"
        return subprocess.check_output(["iwgetid", "-r"], timeout=5).decode().strip() or "Unknown"
    except Exception:
        return "Unknown"


def get_network_info() -> NetworkInfo:
    """Find our IP, gateway and subnet from the OS routing table (via scapy)."""
    info = NetworkInfo(ssid=_ssid())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # no packet is sent for UDP connect
        info.my_ip = s.getsockname()[0]
        s.close()
    except OSError as e:
        log.warning("Could not determine local IP: %s", e)

    try:
        import scapy.route  # noqa: F401  (populates conf.route)
        from scapy.config import conf
        iface, _addr, gw = conf.route.route("0.0.0.0")
        info.iface = str(iface)
        info.gateway = gw if gw != "0.0.0.0" else None
        # Find the connected route that contains our IP to get the real netmask
        for net, mask, _gw, r_iface, _addr2, *_ in conf.route.routes:
            if mask == 0 or str(r_iface) != info.iface:
                continue
            network = ipaddress.IPv4Network(
                (ipaddress.IPv4Address(net), str(ipaddress.IPv4Address(mask))), strict=False)
            if ipaddress.IPv4Address(info.my_ip) in network and 16 <= network.prefixlen <= 30:
                info.subnet = str(network)
                break
        else:
            info.subnet = str(ipaddress.IPv4Network(f"{info.my_ip}/24", strict=False))
    except Exception as e:  # pragma: no cover - depends on host
        log.warning("Could not read routing table: %s", e)
        info.subnet = str(ipaddress.IPv4Network(f"{info.my_ip}/24", strict=False))
    return info


def arp_scan(subnet: str, iface: Optional[str] = None, timeout: float = 2.0) -> List[Device]:
    """Broadcast ARP who-has for every address in the subnet. Needs root/admin."""
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                      timeout=timeout, iface=iface, verbose=0)
    devices = {}
    for _, rcv in answered:
        devices[rcv.psrc] = Device(ip=rcv.psrc, mac=rcv.hwsrc)
    return sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


def demo_devices() -> List[Device]:
    from .simulator import DEVICES
    return [Device(ip=ip, mac=mac, name=name) for ip, mac, name in DEVICES]
