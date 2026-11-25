"""Risk mitigation: blocking IPs on the host firewall.

Three block modes (matching the original project design):

* ``permanent``  - blocked until a user unblocks it ("Isolate device")
* ``temporary``  - blocked for a fixed duration, then removed automatically
* ``auto``       - blocked while the IP keeps attacking; automatically
                   unblocked after a quiet period with no new alerts

Firewall commands are only executed when ``dry_run`` is False. Demo mode and
the test-suite always use dry-run so nothing on the machine is changed.

Note: rules are applied on *this computer's* firewall, so they block traffic
between this computer and the IP. Network-wide isolation requires running the
tool on the gateway/router or integrating with it (see README > Limitations).
"""

import ipaddress
import logging
import platform
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class BlockEntry:
    ip: str
    mode: str                 # permanent | temporary | auto
    since: float
    expires_at: Optional[float] = None
    reason: str = ""


class Firewall:
    """Thin, validated wrapper around iptables / netsh / pfctl."""

    def __init__(self, dry_run: bool = True, system: Optional[str] = None):
        self.dry_run = dry_run
        self.system = system or platform.system()
        self.history: List[str] = []   # every command we ran / would run

    @staticmethod
    def _validate(ip: str) -> str:
        # Never pass unvalidated strings to a shell command.
        return str(ipaddress.ip_address(ip))

    def _commands(self, ip: str, block: bool) -> List[List[str]]:
        if self.system == "Linux":
            op = "-I" if block else "-D"
            return [["iptables", op, "INPUT", "-s", ip, "-j", "DROP"],
                    ["iptables", op, "OUTPUT", "-d", ip, "-j", "DROP"]]
        if self.system == "Windows":
            if block:
                return [["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=IoTGuard_Block_{ip}", f"dir={d}", "action=block",
                         f"remoteip={ip}"] for d in ("in", "out")]
            return [["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name=IoTGuard_Block_{ip}"]]
        if self.system == "Darwin":
            # Requires a pf rule using the table, see docs/SETUP.md
            return [["pfctl", "-t", "iotguard_blocked", "-T", "add" if block else "delete", ip]]
        raise RuntimeError(f"Unsupported OS for firewall control: {self.system}")

    def apply(self, ip: str, block: bool) -> bool:
        ip = self._validate(ip)
        ok = True
        for cmd in self._commands(ip, block):
            self.history.append(("[dry-run] " if self.dry_run else "") + " ".join(cmd))
            if self.dry_run:
                continue
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            except (subprocess.CalledProcessError, FileNotFoundError,
                    subprocess.TimeoutExpired) as e:
                log.error("Firewall command failed: %s (%s)", " ".join(cmd), e)
                ok = False
        return ok


class MitigationManager:
    def __init__(self, firewall: Firewall,
                 last_attack_time: Callable[[str], Optional[float]] = lambda ip: None,
                 auto_quiet_period: float = 60.0,
                 protected_ips: Optional[set] = None):
        self.firewall = firewall
        self.last_attack_time = last_attack_time
        self.auto_quiet_period = auto_quiet_period
        self.protected_ips = set(protected_ips or ())
        self._blocks: Dict[str, BlockEntry] = {}
        self._lock = threading.Lock()
        self.events: List[str] = []

    # -- queries ---------------------------------------------------------
    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocks

    def blocks(self) -> List[BlockEntry]:
        with self._lock:
            return list(self._blocks.values())

    # -- actions ---------------------------------------------------------
    def block(self, ip: str, mode: str, now: float, duration: Optional[float] = None,
              reason: str = "") -> str:
        if mode not in ("permanent", "temporary", "auto"):
            raise ValueError(f"unknown block mode {mode!r}")
        ip = Firewall._validate(ip)
        if ip in self.protected_ips:
            return f"Refused to block {ip}: it is this computer or the gateway"
        with self._lock:
            already = ip in self._blocks
            self._blocks[ip] = BlockEntry(
                ip, mode, now,
                expires_at=now + duration if mode == "temporary" and duration else None,
                reason=reason)
        if not already:
            self.firewall.apply(ip, block=True)
        msg = {"permanent": f"{ip} isolated (blocked until you unblock it)",
               "temporary": f"{ip} blocked for {int(duration or 0)} s",
               "auto": f"{ip} auto-blocked; it will be released after "
                       f"{int(self.auto_quiet_period)} s without attacks"}[mode]
        self.events.append(msg)
        return msg

    def unblock(self, ip: str, why: str = "by user") -> str:
        with self._lock:
            entry = self._blocks.pop(ip, None)
        if entry is None:
            return f"{ip} was not blocked"
        self.firewall.apply(ip, block=False)
        msg = f"{ip} unblocked ({why})"
        self.events.append(msg)
        return msg

    def tick(self, now: float) -> List[str]:
        """Expire temporary blocks and release quiet auto-blocks. Call periodically."""
        released = []
        for entry in self.blocks():
            if entry.mode == "temporary" and entry.expires_at and now >= entry.expires_at:
                released.append(self.unblock(entry.ip, "temporary block expired"))
            elif entry.mode == "auto":
                last = self.last_attack_time(entry.ip) or entry.since
                if now - max(last, entry.since) >= self.auto_quiet_period:
                    released.append(self.unblock(entry.ip, "no attacks during quiet period"))
        return released

    def release_all(self) -> None:
        """Remove every rule we added - called on exit so we never leave rules behind."""
        for entry in self.blocks():
            self.unblock(entry.ip, "application exit")
