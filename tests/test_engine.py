from collections import Counter

import pytest

from iot_guard.detection import Severity, ThreatEngine
from iot_guard.simulator import ATTACK_WINDOWS, ATTACKER, Scenario, generate


@pytest.fixture(scope="module")
def full_run():
    engine = ThreatEngine()
    results = [(label, engine.analyze(p)) for p, label in generate(Scenario())]
    return engine, results


def test_no_false_alarms_on_benign_traffic(full_run):
    _, results = full_run
    benign_attacks = sum(v.is_attack for label, v in results if label == "normal")
    assert benign_attacks == 0


def test_every_attack_type_is_detected(full_run):
    _, results = full_run
    detected = Counter(label for label, v in results if label != "normal" and v.is_attack)
    for attack in ATTACK_WINDOWS:
        total = sum(1 for label, _ in results if label == attack)
        assert detected[attack] / total > 0.8, attack


def test_attacker_is_top_offender(full_run):
    engine, _ = full_run
    top = engine.offenders()[0]
    assert top.ip == ATTACKER and top.worst == Severity.CRITICAL


def test_ml_model_trains_after_warmup(full_run):
    engine, _ = full_run
    assert engine.ml.trained


def test_blocked_source_is_marked_but_still_tracked():
    engine = ThreatEngine(use_ml=False, is_blocked=lambda ip: ip == ATTACKER)
    verdicts = [engine.analyze(p) for p, label in generate(Scenario()) if label == "syn_flood"]
    assert all(v.severity == Severity.BLOCKED for v in verdicts)
    # detection keeps running so auto-unblock can tell whether the attack stopped
    assert engine.last_attack_time(ATTACKER) is not None
