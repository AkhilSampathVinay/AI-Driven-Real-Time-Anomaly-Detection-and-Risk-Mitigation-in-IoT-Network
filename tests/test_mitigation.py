import pytest

from iot_guard.mitigation import Firewall, MitigationManager


def make(last_attack=None, **kw):
    fw = Firewall(dry_run=True, system="Linux")
    return fw, MitigationManager(fw, last_attack_time=lambda ip: last_attack, **kw)


def test_dry_run_records_commands_without_running_them():
    fw, mm = make()
    mm.block("10.0.0.5", "permanent", now=0)
    assert mm.is_blocked("10.0.0.5")
    assert fw.history[0].startswith("[dry-run] iptables -I INPUT -s 10.0.0.5")


def test_rejects_command_injection():
    _, mm = make()
    with pytest.raises(ValueError):
        mm.block("10.0.0.5; rm -rf /", "permanent", now=0)


def test_refuses_to_block_protected_ip():
    _, mm = make(protected_ips={"192.168.1.1"})
    msg = mm.block("192.168.1.1", "permanent", now=0)
    assert "Refused" in msg and not mm.is_blocked("192.168.1.1")


def test_temporary_block_expires():
    _, mm = make()
    mm.block("10.0.0.5", "temporary", now=100, duration=60)
    assert mm.tick(150) == [] and mm.is_blocked("10.0.0.5")
    assert mm.tick(161) and not mm.is_blocked("10.0.0.5")


def test_auto_block_released_after_quiet_period():
    state = {"last": 100.0}
    fw = Firewall(dry_run=True, system="Linux")
    mm = MitigationManager(fw, last_attack_time=lambda ip: state["last"], auto_quiet_period=30)
    mm.block("10.0.0.5", "auto", now=100)
    state["last"] = 120          # attacker still active
    assert mm.tick(140) == []
    assert mm.tick(151)          # 31 s since last attack -> released
    assert not mm.is_blocked("10.0.0.5")


def test_permanent_block_is_never_auto_released():
    _, mm = make()
    mm.block("10.0.0.5", "permanent", now=0)
    assert mm.tick(10**9) == [] and mm.is_blocked("10.0.0.5")


def test_release_all_on_exit_and_windows_commands():
    fw = Firewall(dry_run=True, system="Windows")
    mm = MitigationManager(fw)
    mm.block("10.0.0.5", "permanent", now=0)
    mm.release_all()
    assert not mm.blocks()
    assert any("dir=out" in c for c in fw.history)
    assert any("delete rule" in c for c in fw.history)
