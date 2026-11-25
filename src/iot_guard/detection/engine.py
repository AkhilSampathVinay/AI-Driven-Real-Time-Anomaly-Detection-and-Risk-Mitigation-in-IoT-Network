"""ThreatEngine - runs every detector on each packet and keeps offender stats."""

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from scapy.layers.inet import IP

from ..config import Config
from .ml import BehaviorModel
from .rules import DnsTunnelDetector, FloodDetector, MiraiDetector, ScanDetector
from .verdict import Alert, Severity, Verdict


@dataclass
class Offender:
    ip: str
    first_seen: float
    last_seen: float
    alerts: int = 0
    categories: Counter = field(default_factory=Counter)
    worst: Severity = Severity.NORMAL


class ThreatEngine:
    def __init__(self, config: Optional[Config] = None, use_ml: bool = True,
                 is_blocked: Callable[[str], bool] = lambda ip: False):
        self.config = config or Config()
        t = self.config.thresholds
        self.mirai = MiraiDetector(self.config.mirai)
        self.rule_detectors = [FloodDetector(t), ScanDetector(t), DnsTunnelDetector(t)]
        self.ml = BehaviorModel(t) if use_ml else None
        self.is_blocked = is_blocked
        self._lock = threading.Lock()
        self._offenders: Dict[str, Offender] = {}
        self.stats = Counter()

    def analyze(self, pkt) -> Verdict:
        verdict = Verdict()
        ts = float(getattr(pkt, "time", None) or time.time())

        # Blocked sources are still analysed (libpcap sees packets before the
        # firewall drops them) so auto-unblock knows whether the attack stopped.
        blocked = pkt.haslayer(IP) and self.is_blocked(pkt[IP].src)

        alert = self.mirai.check(pkt)
        if alert:
            verdict.add(alert)
        for det in self.rule_detectors:
            alert = det.check(pkt, ts)
            if alert:
                verdict.add(alert)

        if self.ml is not None and not blocked:
            alert = self.ml.observe(pkt, ts, flagged_by_rules=bool(verdict.alerts))
            if alert:
                verdict.add(alert)

        for a in verdict.alerts:
            if a.severity >= Severity.WARNING and a.src:
                self._record(a, ts)
        if blocked:
            verdict.add(Alert(Severity.BLOCKED, "blocked",
                              "Source is blocked by a mitigation rule", pkt[IP].src))
        self.stats[verdict.severity.name] += 1
        return verdict

    def _record(self, alert: Alert, ts: float) -> None:
        with self._lock:
            off = self._offenders.get(alert.src)
            if off is None:
                off = self._offenders[alert.src] = Offender(alert.src, ts, ts)
            off.last_seen = ts
            off.alerts += 1
            off.categories[alert.category] += 1
            off.worst = max(off.worst, alert.severity)

    def offenders(self) -> list:
        """Snapshot of offending IPs, worst first (safe to call from the GUI thread)."""
        with self._lock:
            items = list(self._offenders.values())
        return sorted(items, key=lambda o: (o.worst, o.alerts), reverse=True)

    def last_attack_time(self, ip: str) -> Optional[float]:
        with self._lock:
            off = self._offenders.get(ip)
            return off.last_seen if off else None
