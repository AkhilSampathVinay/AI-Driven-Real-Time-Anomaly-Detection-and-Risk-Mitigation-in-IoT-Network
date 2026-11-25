"""Result types returned by the detection engine."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    NORMAL = 0
    NOTICE = 1    # ML behavioural anomaly - worth a look, not an attack on its own
    WARNING = 2   # rate / heuristic based attack (flood, scan, tunneling)
    CRITICAL = 3  # known malware signature (Mirai)
    BLOCKED = 4   # traffic from an IP we already blocked


@dataclass
class Alert:
    severity: Severity
    category: str          # e.g. "mirai", "syn_flood", "port_scan"
    message: str
    src: Optional[str] = None
    dst: Optional[str] = None


@dataclass
class Verdict:
    severity: Severity = Severity.NORMAL
    alerts: List[Alert] = field(default_factory=list)

    def add(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if alert.severity > self.severity:
            self.severity = alert.severity

    @property
    def is_attack(self) -> bool:
        """WARNING or CRITICAL - what we count as a real detection."""
        return Severity.WARNING <= self.severity <= Severity.CRITICAL

    @property
    def summary(self) -> str:
        if not self.alerts:
            return "Traffic within expected parameters"
        return " | ".join(a.message for a in self.alerts)
