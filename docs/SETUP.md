# Setup details

## Requirements

- Python 3.9+
- Tkinter (bundled with Python on Windows/macOS; on Debian/Ubuntu run `sudo apt install python3-tk`)
- For **live** mode only:
  - Linux / macOS: run with `sudo`
  - Windows: an *Administrator* terminal and [Npcap](https://npcap.com/) (install it in "WinPcap API-compatible mode")

Demo mode, `analyze`, `generate`, `evaluate` and the tests need **no** special privileges.

## Install

```bash
git clone https://github.com/AkhilSampathVinay/AI-Driven-Real-Time-Anomaly-Detection-and-Risk-Mitigation-in-IoT-Network.git
cd AI-Driven-Real-Time-Anomaly-Detection-and-Risk-Mitigation-in-IoT-Network
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

## Live mode

```bash
sudo .venv/bin/iot-guard live            # detect + show what it *would* block (dry-run)
sudo .venv/bin/iot-guard live --enforce  # actually add firewall rules
```

On startup, live mode reads your IP, gateway and subnet from the routing table,
ARP-scans the subnet and starts capturing. It refuses to block your own IP or the
gateway.

### What live mode can see

On a normal switched or Wi-Fi network a computer only sees **its own traffic plus
broadcast/multicast**, not traffic between two other devices. To monitor every
IoT device, run IoT Guard on a machine that traffic flows through, for example:

- the router/gateway itself, or a Raspberry Pi set up as the gateway / access point
- a switch port with port mirroring (SPAN) enabled
- a Linux box acting as a bridge in front of the IoT devices

### Firewall notes

| OS | Mechanism | Notes |
|---|---|---|
| Linux | `iptables -I INPUT/OUTPUT … -j DROP` | needs root |
| Windows | `netsh advfirewall firewall add rule` (in + out) | needs Administrator |
| macOS | `pfctl -t iotguard_blocked -T add` | needs a pf rule that uses the table, e.g. add `table <iotguard_blocked> persist` and `block drop quick from <iotguard_blocked>` to `/etc/pf.conf`, then `sudo pfctl -f /etc/pf.conf -e` |

Rules only affect traffic between **this computer** and the blocked IP. All rules
IoT Guard added are removed when the app closes.

## Tuning

Thresholds are in `src/iot_guard/config.py` (window sizes, packet counts, DNS
entropy, ML score threshold). After changing them, run `iot-guard evaluate` to see
the effect on precision and recall.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: tkinter` | `sudo apt install python3-tk` (Linux) or reinstall Python with Tcl/Tk (macOS/Windows) |
| `Permission denied` / `Operation not permitted` on capture | run live mode with sudo / as Administrator |
| Windows: `No libpcap provider available` | install Npcap |
| No devices found by the scan | check you're on the right network; some devices don't answer ARP while asleep, so press *Scan network* again |
