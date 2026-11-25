"""Headless analysis of a PCAP file and evaluation on labelled synthetic traffic."""

import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from scapy.utils import PcapReader

from .detection import Severity, ThreatEngine


@dataclass
class AnalysisReport:
    packets: int = 0
    seconds: float = 0.0
    severities: Counter = field(default_factory=Counter)
    categories: Counter = field(default_factory=Counter)
    first_alerts: List[Tuple[float, str, str]] = field(default_factory=list)
    offenders: list = field(default_factory=list)

    def render(self) -> str:
        lines = ["", "=" * 64, " IoT Guard - analysis report", "=" * 64,
                 f" Packets analysed : {self.packets:,}",
                 f" Processing time  : {self.seconds:.1f} s "
                 f"({self.packets / max(self.seconds, 1e-9):,.0f} packets/s)", "",
                 " Verdicts:"]
        for sev in Severity:
            if self.severities.get(sev.name):
                lines.append(f"   {sev.name:<9}{self.severities[sev.name]:>8,}")
        if self.categories:
            lines += ["", " Detections by type:"]
            for cat, n in self.categories.most_common():
                lines.append(f"   {cat:<12}{n:>8,}")
        if self.first_alerts:
            lines += ["", " First occurrence of each threat:"]
            for t, cat, msg in self.first_alerts:
                lines.append(f"   +{t:7.1f}s  {cat:<11} {msg}")
        if self.offenders:
            lines += ["", " Top offending IPs:"]
            for o in self.offenders[:10]:
                cats = ", ".join(f"{c}={n}" for c, n in o.categories.most_common())
                lines.append(f"   {o.ip:<16} {o.worst.name:<9} {o.alerts:>6} alerts  ({cats})")
        lines.append("=" * 64)
        return "\n".join(lines)


def analyze_packets(packets: Iterable, engine: Optional[ThreatEngine] = None) -> AnalysisReport:
    engine = engine or ThreatEngine()
    rep = AnalysisReport()
    seen = set()
    start_ts = None
    t0 = time.perf_counter()
    for pkt in packets:
        ts = float(pkt.time)
        start_ts = ts if start_ts is None else start_ts
        v = engine.analyze(pkt)
        rep.packets += 1
        rep.severities[v.severity.name] += 1
        for a in v.alerts:
            if a.severity >= Severity.WARNING:
                rep.categories[a.category] += 1
            if a.category not in seen and a.severity >= Severity.WARNING:
                seen.add(a.category)
                rep.first_alerts.append((ts - start_ts, a.category, a.message))
    rep.seconds = time.perf_counter() - t0
    rep.offenders = engine.offenders()
    return rep


def analyze_pcap(path: str, use_ml: bool = True) -> AnalysisReport:
    with PcapReader(path) as reader:
        return analyze_packets(reader, ThreatEngine(use_ml=use_ml))


# ---------------------------------------------------------------- evaluation

def evaluate(seed: int = 7) -> str:
    """Evaluate on labelled synthetic traffic.

    Reports (1) the false-positive rate on benign packets, (2) whether every
    attack was detected and how quickly, and (3) packet-level precision /
    recall for the rule engine and the ML model separately.
    """
    from .simulator import ATTACK_WINDOWS, Scenario, generate

    data = generate(Scenario(seed=seed))
    engine = ThreatEngine()
    t_start = float(data[0][0].time)

    rule_tp = rule_fp = rule_fn = 0
    ml_tp = ml_fp = ml_fn = 0
    benign = 0
    detect_time: Dict[str, float] = {}
    per_label = defaultdict(Counter)

    for pkt, label in data:
        v = engine.analyze(pkt)
        attack = label != "normal"
        benign += not attack
        rule_hit = v.is_attack
        ml_hit = any(a.category == "behavior" for a in v.alerts)
        per_label[label]["total"] += 1
        per_label[label]["rules"] += rule_hit
        per_label[label]["ml"] += ml_hit

        if attack and rule_hit and label not in detect_time:
            detect_time[label] = float(pkt.time) - t_start - ATTACK_WINDOWS[label][0]

        rule_tp += attack and rule_hit
        rule_fp += (not attack) and rule_hit
        rule_fn += attack and not rule_hit
        ml_tp += attack and ml_hit
        ml_fp += (not attack) and ml_hit
        ml_fn += attack and not ml_hit

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return p, r, f

    rp, rr, rf = prf(rule_tp, rule_fp, rule_fn)
    mp, mr, mf = prf(ml_tp, ml_fp, ml_fn)
    out = ["", "Evaluation on synthetic labelled traffic "
               f"({len(data):,} packets, seed={seed})", "-" * 64,
           f"{'Detector':<22}{'Precision':>10}{'Recall':>10}{'F1':>8}{'Benign FPR':>13}",
           f"{'Rules (WARN/CRIT)':<22}{rp:>10.3f}{rr:>10.3f}{rf:>8.3f}{rule_fp / benign:>12.2%}",
           f"{'Isolation Forest':<22}{mp:>10.3f}{mr:>10.3f}{mf:>8.3f}{ml_fp / benign:>12.2%}",
           "", f"{'Attack':<12}{'Packets':>9}{'Rules':>9}{'ML':>9}{'Alert raised after':>21}"]
    for label in ATTACK_WINDOWS:
        c = per_label[label]
        dt = detect_time.get(label)
        out.append(f"{label:<12}{c['total']:>9}{c['rules'] / c['total']:>9.0%}"
                   f"{c['ml'] / c['total']:>9.0%}"
                   f"{(f'{dt:.2f} s' if dt is not None else 'MISSED'):>21}")
    out.append("")
    out.append("Rules = signature + rate detectors. ML = behavioural model (NOTICE level).")
    out.append("Packet-level recall for floods/scans is <100% by design: a flood is only")
    out.append("recognisable after its rate crosses the threshold.")
    return "\n".join(out)
