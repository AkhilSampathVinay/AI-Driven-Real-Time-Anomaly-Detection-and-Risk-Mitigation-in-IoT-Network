# Changelog

## v2.0.0: refactor and detection overhaul

v1 was the single-file prototype built for the B.Tech major project
(kept unchanged in [`legacy/main_original.py`](../legacy/main_original.py)).
v2 restructures it into a tested package and fixes the issues below.

### Measured on the same synthetic traffic (15,088 packets)

| | v1 | v2 |
|---|---|---|
| Benign packets raising WARNING/CRITICAL | **99.8 %** (7,574 / 7,586) | **0 %** |
| Benign packets labelled CRITICAL "Mirai" | 160 | 0 |
| UDP flood detected | **no** (0 / 4,000 packets) | yes, within 1.3 s |
| Port scan / SYN flood | detected but labelled as "Mirai" | correct type |
| DNS tunneling | flagged only by the generic ML/size checks | dedicated detector |
| Analysis speed (with ML) | one sklearn call per packet (several ms) | ~0.5 ms / packet |
| Runs without root / a real network | no | yes (`iot-guard demo`) |
| Automated tests | none | 29 tests + CI |

### Detection fixes

- **"Unusual TCP flags" rule was inverted.** It fired whenever a flow had *not*
  used FIN/RST/URG/PSH, which is true of nearly every flow, so almost every TCP
  packet was a WARNING.
- **Every new connection was flagged as a "Mirai SYN scan".** Any SYN from an IP
  other than the monitored device raised CRITICAL. Replaced with real port-scan /
  sweep detection plus the Mirai scanner fingerprint (TCP `seq == destination IP`).
- **Payloads were matched against `str(bytes)`** (the `b'...'` repr), which broke
  the `^root:` regex and made escaped bytes match keywords. Matching now uses raw
  bytes with Mirai's actual credential and loader strings.
- **Rates were measured over the whole flow lifetime**, so floods were diluted
  and missed. All rate rules now use sliding windows.
- **DNS layer was never classified**, because DNS was checked after UDP.
- **Isolation Forest** was trained on unscaled features, contamination was fixed
  at 5% (so 5% of traffic was *always* anomalous), it was retrained on attack
  traffic, and it cost ~5 ms per packet. Fixed with scaling, a score threshold,
  training only on clean traffic, and a score cache.

### Mitigation fixes

- **Auto-unblock never worked.** The method feeding it (`_silent_analysis`) was
  never called and referenced an attribute that didn't exist (`analysis_buffer`).
- **Temporary blocks never expired.** The duration was stored but never checked.
- Blocked IPs are now still analysed (libpcap sees packets before the firewall
  drops them), which is what makes auto-unblock possible.
- IPs are validated before being passed to firewall commands, the gateway and
  your own IP can't be blocked, Windows blocks both directions, firewall rules
  are removed on exit, and dry-run is the default.

### GUI / runtime fixes

- **The first network scan always showed an empty list.** The scan thread
  started and the list was read immediately, before the scan finished.
- **Tkinter was updated from background threads**, which isn't thread-safe and
  causes random freezes or crashes. All widget updates now happen on the main
  thread.
- **"Stop" could hang** because `sniff(stop_filter=…)` only checks the flag when
  a packet arrives. Now uses `AsyncSniffer`.
- The packet graph broke after 10,000 packets (ring buffer read out of order),
  and the packet cache was keyed by summary text (collisions, unbounded memory).
- One capture and one engine for the whole network, instead of a separate
  capture and analyser per device window.

### New

- `iot-guard demo`: simulated smart-home network with scripted attacks
- `iot-guard analyze FILE.pcap`: headless report
- `iot-guard evaluate`: precision, recall and time-to-detect
- `iot-guard generate`: write the scenario to a PCAP for Wireshark
- Alert grouping, per-device inspector, report export, firewall command log
