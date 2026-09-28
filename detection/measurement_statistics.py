"""No machine learning or trained models are used in this module.

Measurement statistics are computed with binomial proportions and a fixed
baseline, making every detection decision mathematically auditable.
"""

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class MeasurementStatistics:
	"""Observed error rate and its standard-score deviation from baseline."""

	rounds: int
	mismatches: int
	error_rate: float
	expected_error_rate: float
	deviation: float
	z_score: float


def compute_statistics(matches: list[bool], expected_error_rate: float = 0.0) -> MeasurementStatistics:
	"""Aggregate Boolean verification outcomes into QBER-style statistics."""
	if not matches:
		raise ValueError("at least one verification result is required")
	if not 0 <= expected_error_rate < 1:
		raise ValueError("expected_error_rate must be in [0, 1)")
	mismatches = sum(not match for match in matches)
	rounds = len(matches)
	error_rate = mismatches / rounds
	deviation = abs(error_rate - expected_error_rate)
	sigma = math.sqrt(expected_error_rate * (1 - expected_error_rate) / rounds)
	if sigma == 0:
		z_score = float("inf") if deviation else 0.0
	else:
		z_score = deviation / sigma
	return MeasurementStatistics(rounds, mismatches, error_rate, expected_error_rate, deviation, z_score)
