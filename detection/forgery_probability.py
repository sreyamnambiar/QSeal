"""No machine learning or trained models are used in this module."""

import math

from config import DEFAULT_FORGERY_SUCCESS_PROBABILITY


def forgery_probability(num_rounds: int, per_round_success_prob: float = DEFAULT_FORGERY_SUCCESS_PROBABILITY) -> float:
	"""Compute independent-round forgery success as ``p**N``."""
	if num_rounds < 0 or not 0 <= per_round_success_prob <= 1:
		raise ValueError("rounds must be nonnegative and probability must be in [0, 1]")
	return per_round_success_prob ** num_rounds


def rounds_for_probability(target_probability: float, per_round_success_prob: float = DEFAULT_FORGERY_SUCCESS_PROBABILITY) -> int:
	"""Return the smallest round count whose probability is at most target."""
	if not 0 < target_probability <= 1 or not 0 < per_round_success_prob < 1:
		raise ValueError("target and per-round probability must be in (0, 1]")
	return math.ceil(math.log(target_probability) / math.log(per_round_success_prob))
