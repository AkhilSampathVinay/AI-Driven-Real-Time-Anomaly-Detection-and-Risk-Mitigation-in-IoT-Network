"""Packet sources: live capture, PCAP replay and synthetic demo traffic.

Every source runs in a background thread and calls ``callback(packet)`` for
each packet. ``stop()`` always returns promptly (the original version used
``sniff(stop_filter=...)``, which only checked the flag when a new packet
arrived, so "Stop" could hang on a quiet network).
"""

import threading
import time
from typing import Callable, Iterable, Optional

from scapy.utils import PcapReader

Callback = Callable[[object], None]


class PacketSource:
    name = "source"

    def __init__(self):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self, callback: Callback) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(callback,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self, callback: Callback) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


class LiveSource(PacketSource):
    """Live capture with scapy's AsyncSniffer. Needs root / Administrator + Npcap."""
    name = "live"

    def __init__(self, bpf_filter: Optional[str] = None, iface: Optional[str] = None):
        super().__init__()
        self.bpf_filter = bpf_filter
        self.iface = iface
        self._sniffer = None

    def start(self, callback: Callback) -> None:
        from scapy.sendrecv import AsyncSniffer
        self._sniffer = AsyncSniffer(filter=self.bpf_filter, iface=self.iface,
                                     prn=callback, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

    @property
    def running(self) -> bool:
        return bool(self._sniffer and self._sniffer.running)


class ReplaySource(PacketSource):
    """Replays packets preserving their original timing (scaled by ``speed``)."""
    name = "replay"

    def __init__(self, packets: Callable[[], Iterable], speed: float = 1.0, loop: bool = False,
                 retime: bool = True):
        super().__init__()
        self._packets = packets
        self.speed = speed
        self.loop = loop
        self.retime = retime  # rewrite timestamps to "now" so the GUI clock is live

    def _run(self, callback: Callback) -> None:
        # Timestamps keep their original spacing (not divided by speed) so the
        # detectors see the same packet rates no matter how fast we replay.
        base = time.time() if self.retime else None
        offset = 0.0
        while not self._stop.is_set():
            wall_start = time.time()
            first = None
            last_ts = 0.0
            for pkt in self._packets():
                if self._stop.is_set():
                    return
                ts = float(pkt.time)
                if first is None:
                    first = ts
                delay = wall_start + (ts - first) / self.speed - time.time()
                if delay > 0 and self._stop.wait(delay):
                    return
                last_ts = ts
                pkt.time = (base + offset + ts - first) if self.retime else ts + offset
                callback(pkt)
            if not self.loop or first is None:
                return
            offset += last_ts - first + 1.0


def pcap_source(path: str, speed: float = 1.0, loop: bool = False) -> ReplaySource:
    def packets():
        with PcapReader(path) as reader:
            yield from reader
    return ReplaySource(packets, speed=speed, loop=loop)


def demo_source(speed: float = 2.0, loop: bool = True) -> ReplaySource:
    from .simulator import Scenario, generate

    cache = []

    def packets():
        if not cache:
            cache.extend(p for p, _ in generate(Scenario()))
        # copy so retiming does not mutate the cached originals
        return (p.copy() for p in cache)
    return ReplaySource(packets, speed=speed, loop=loop)
