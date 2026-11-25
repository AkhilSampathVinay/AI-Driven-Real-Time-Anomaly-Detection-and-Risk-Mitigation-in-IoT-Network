import time

from iot_guard.__main__ import main
from iot_guard.detection import Verdict
from iot_guard.gui import format as fmt
from iot_guard.monitor import Monitor
from iot_guard.simulator import Scenario, generate
from iot_guard.sources import ReplaySource, demo_source


def test_generate_and_analyze_pcap(tmp_path, capsys):
    out = tmp_path / "demo.pcap"
    assert main(["generate", str(out)]) == 0
    assert out.stat().st_size > 0
    assert main(["analyze", str(out), "--no-ml"]) == 0
    report = capsys.readouterr().out
    for word in ("mirai", "syn_flood", "udp_flood", "port_scan", "dns_tunnel"):
        assert word in report


def test_replay_source_stops_promptly():
    pkts = [p for p, _ in generate(Scenario(duration=30, attacks=False))]
    received = []
    src = ReplaySource(lambda: iter(pkts), speed=1.0)
    src.start(received.append)
    time.sleep(0.5)
    t0 = time.time()
    src.stop()
    assert time.time() - t0 < 1.0 and not src.running
    assert 0 < len(received) < len(pkts)


def test_monitor_end_to_end_with_fast_demo():
    mon = Monitor(lambda: demo_source(speed=200, loop=False))
    mon.start()
    deadline = time.time() + 60
    while mon.running and time.time() < deadline:
        mon.drain()
        time.sleep(0.05)
    mon.drain()
    assert mon.total > 10000 and mon.total_attacks > 1000
    assert mon.engine.offenders()


def test_packet_formatting_does_not_crash():
    for p, _ in generate(Scenario())[:2000:7]:
        assert fmt.summary(p, Verdict())
        assert "Packet analysis" in fmt.details(p, Verdict())
