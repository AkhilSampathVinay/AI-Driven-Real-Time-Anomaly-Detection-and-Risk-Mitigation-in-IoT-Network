"""Unsupervised behavioural anomaly detection with an Isolation Forest.

The model learns what "normal" traffic looks like for the monitored network
during a warm-up period, then scores every new packet. It is retrained
periodically on recent traffic, *excluding* packets the rule engine already
flagged, so attacks do not get learned as normal behaviour (model poisoning).
"""

from collections import deque
from typing import Dict, Optional

import numpy as np
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ..config import Thresholds
from .verdict import Alert, Severity

FEATURE_NAMES = [
    "log_size", "log_inter_arrival_same_src", "protocol",
    "dst_port_class", "is_syn", "has_payload",
]


def _port_class(port: int) -> int:
    if port < 1024:
        return 0
    if port < 49152:
        return 1
    return 2


class FeatureExtractor:
    """Turns a packet into a small numeric feature vector."""

    def __init__(self):
        self._last_seen: Dict[str, float] = {}

    def extract(self, pkt, ts: float) -> Optional[np.ndarray]:
        if not pkt.haslayer(IP):
            return None
        src = pkt[IP].src
        prev = self._last_seen.get(src)
        self._last_seen[src] = ts
        gap = 1.0 if prev is None else max(ts - prev, 0.0)

        proto, dport, syn = 0, 0, 0
        if pkt.haslayer(DNS):
            proto = 3
            dport = 53
        elif pkt.haslayer(TCP):
            proto, dport = 1, pkt[TCP].dport
            syn = int(bool(int(pkt[TCP].flags) & 0x02) and not int(pkt[TCP].flags) & 0x10)
        elif pkt.haslayer(UDP):
            proto, dport = 2, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = 4

        payload = len(pkt[IP].payload.payload) if pkt[IP].payload else 0
        return np.array([
            np.log1p(len(pkt)), np.log1p(gap * 1000), proto,
            _port_class(dport), syn, int(payload > 0),
        ], dtype=float)


class BehaviorModel:
    def __init__(self, t: Thresholds, buffer_size: int = 5000, seed: int = 42):
        self.t = t
        self.seed = seed
        self.features = FeatureExtractor()
        self.buffer = deque(maxlen=buffer_size)
        self.model = None
        self.last_trained_at: Optional[float] = None
        self._score_cache: dict = {}
        self.last_score: Optional[float] = None

    @property
    def trained(self) -> bool:
        return self.model is not None

    def _train(self, now: float) -> None:
        X = np.vstack(self.buffer)
        self.model = make_pipeline(
            StandardScaler(),
            IsolationForest(n_estimators=100, contamination="auto", random_state=self.seed),
        )
        self.model.fit(X)
        self.last_trained_at = now
        self._score_cache = {}

    def score(self, x: np.ndarray) -> float:
        """Isolation Forest score, cached on a rounded feature vector.

        Calling sklearn once per packet costs ~5 ms (mostly per-call overhead);
        network traffic is highly repetitive, so a small cache keeps scoring
        well under 0.1 ms per packet in practice.
        """
        key = tuple(np.round(x, 1))
        s = self._score_cache.get(key)
        if s is None:
            s = float(self.model.decision_function(x.reshape(1, -1))[0])
            if len(self._score_cache) > 50_000:
                self._score_cache.clear()
            self._score_cache[key] = s
        return s

    def observe(self, pkt, ts: float, flagged_by_rules: bool) -> Optional[Alert]:
        x = self.features.extract(pkt, ts)
        if x is None:
            return None

        alert = None
        if self.trained:
            score = self.last_score = self.score(x)
            if score < self.t.ml_score_threshold:
                alert = Alert(Severity.NOTICE, "behavior",
                              f"Behavioural anomaly (Isolation Forest score {score:.2f})",
                              pkt[IP].src, pkt[IP].dst)

        # Only learn from traffic that looked clean to every detector.
        if not flagged_by_rules and alert is None:
            self.buffer.append(x)

        if not self.trained and len(self.buffer) >= self.t.ml_warmup_packets:
            self._train(ts)
        elif self.trained and ts - self.last_trained_at > self.t.ml_retrain_interval:
            self._train(ts)
        return alert
