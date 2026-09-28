"""Regression tests for fixed statistical detection rules."""

from detection.decision_engine import decide
from detection.forgery_probability import forgery_probability, rounds_for_probability
from detection.measurement_statistics import compute_statistics
from detection.threshold_engine import exceeds_threshold


def test_qber_and_threshold() -> None:
    """Mismatch proportions are computed directly and use the fixed QBER limit."""
    statistics = compute_statistics([True] * 89 + [False] * 11)
    assert statistics.error_rate == 0.11
    assert not exceeds_threshold(statistics.error_rate)
    assert exceeds_threshold(0.12)


def test_forgery_probability_decays() -> None:
    """Independent verification rounds produce exponential decay."""
    assert forgery_probability(4) == 0.75**4
    assert forgery_probability(rounds_for_probability(1e-6)) <= 1e-6


def test_attack_decisions_are_explicit() -> None:
    """Attack labels and stale sessions map to the required verdict names."""
    assert decide([True, True], attack_type="forgery").verdict == "REJECT_FORGERY"
    assert decide([True, True], attack_type="impersonation", key_id="attacker").verdict == "REJECT_IMPERSONATION"
    assert decide([True, True], session_id=2, expected_session_id=2).verdict == "REJECT_REPLAY"
    assert decide([False, True], attack_type="channel_manipulation").verdict == "REJECT_TAMPERED"