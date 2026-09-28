"""No machine learning or trained models are used in this module."""

from dataclasses import dataclass

from config import BASELINE_ERROR_RATE, QBER_THRESHOLD
from detection.forgery_probability import forgery_probability
from detection.measurement_statistics import MeasurementStatistics, compute_statistics
from detection.threshold_engine import exceeds_threshold


@dataclass(frozen=True)
class Decision:
	"""Auditable result of threshold, attack, and freshness rules."""

	verdict: str
	error_rate: float
	confidence: float
	statistics: MeasurementStatistics


def decide(
	matches: list[bool],
	attack_type: str | None = None,
	session_id: int | None = None,
	expected_session_id: int | None = None,
	key_id: str = "legitimate",
) -> Decision:
	"""Combine QBER thresholding with explicit replay and attack labels."""
	statistics = compute_statistics(matches, BASELINE_ERROR_RATE)
	error = statistics.error_rate
	confidence = min(1.0, error / QBER_THRESHOLD) if QBER_THRESHOLD else 1.0
	if session_id is not None and expected_session_id is not None and session_id <= expected_session_id:
		verdict = "REJECT_REPLAY"
	elif key_id != "legitimate" or attack_type == "impersonation":
		verdict = "REJECT_IMPERSONATION"
	elif attack_type == "replay":
		verdict = "REJECT_REPLAY"
	elif attack_type == "forgery" or exceeds_threshold(error):
		verdict = "REJECT_FORGERY" if attack_type != "channel_manipulation" else "REJECT_TAMPERED"
	elif attack_type == "channel_manipulation":
		verdict = "REJECT_TAMPERED" if exceeds_threshold(error) else "ACCEPT"
	else:
		verdict = "ACCEPT"
	return Decision(verdict, error, confidence, statistics)
