"""Monitor - glue between a packet source, the threat engine and mitigation.

Has no GUI code, so it can be unit-tested and reused (e.g. a future web UI).
Packets are analysed on the capture thread; results are handed to the GUI
through a bounded queue, which the GUI drains on its own (main) thread.
Tkinter is not thread-safe, so the GUI never gets touched from here.
"""

import queue
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from scapy.layers.inet import IP

from .detection import Severity, ThreatEngine, Verdict
from .mitigation import Firewall, MitigationManager
from .sources import PacketSource


@dataclass
class DeviceStats:
    packets: int = 0
    sent: int = 0
    attacks: int = 0
    notices: int = 0
    last_attack: str = ""
    recent: deque = field(default_factory=lambda: deque(maxlen=2000))  # (pkt, verdict)


class Monitor:
    def __init__(self, source_factory, dry_run: bool = True, protected_ips=(),
                 auto_quiet_period: float = 30.0):
        self.source_factory = source_factory
        self.source: Optional[PacketSource] = None
        self.firewall = Firewall(dry_run=dry_run)
        self.engine = ThreatEngine()
        self.mitigation = MitigationManager(
            self.firewall, last_attack_time=self.engine.last_attack_time,
            auto_quiet_period=auto_quiet_period, protected_ips=set(protected_ips))
        self.engine.is_blocked = self.mitigation.is_blocked
        self.results: "queue.Queue[Tuple[object, Verdict]]" = queue.Queue(maxsize=20000)
        self.dropped = 0
        self.devices: Dict[str, DeviceStats] = {}
        self.timeline: deque = deque(maxlen=600)  # [second, packets, attacks]
        self.total = 0
        self.total_attacks = 0
        self.latest_ts = time.time()

    # -- capture thread ---------------------------------------------------
    def _on_packet(self, pkt) -> None:
        try:
            verdict = self.engine.analyze(pkt)
        except Exception:  # never let one malformed packet kill the capture
            return
        try:
            self.results.put_nowait((pkt, verdict))
        except queue.Full:
            self.dropped += 1

    # -- control ----------------------------------------------------------
    def start(self) -> None:
        if self.source and self.source.running:
            return
        self.source = self.source_factory()
        self.source.start(self._on_packet)

    def stop(self) -> None:
        if self.source:
            self.source.stop()

    @property
    def running(self) -> bool:
        return bool(self.source and self.source.running)

    def shutdown(self) -> None:
        self.stop()
        self.mitigation.release_all()

    # -- GUI thread -------------------------------------------------------
    def drain(self, limit: int = 5000) -> List[Tuple[object, Verdict]]:
        """Pull analysed packets off the queue and update statistics."""
        batch = []
        for _ in range(limit):
            try:
                batch.append(self.results.get_nowait())
            except queue.Empty:
                break
        for pkt, v in batch:
            self.total += 1
            ts = float(pkt.time)
            self.latest_ts = ts
            sec = int(ts)
            if not self.timeline or self.timeline[-1][0] != sec:
                self.timeline.append([sec, 0, 0])
            self.timeline[-1][1] += 1
            if v.is_attack:
                self.total_attacks += 1
                self.timeline[-1][2] += 1
            if pkt.haslayer(IP):
                for ip in {pkt[IP].src, pkt[IP].dst}:
                    d = self.devices.get(ip)
                    if d is None:
                        d = self.devices[ip] = DeviceStats()
                    d.packets += 1
                    if ip == pkt[IP].src:
                        d.sent += 1
                    d.recent.append((pkt, v))
                    if v.is_attack:
                        d.attacks += 1
                        d.last_attack = v.alerts[0].category
                    elif v.severity == Severity.NOTICE:
                        d.notices += 1
        return batch

    def tick(self) -> List[str]:
        """Expire / auto-release blocks using the traffic clock."""
        return self.mitigation.tick(self.latest_ts)
