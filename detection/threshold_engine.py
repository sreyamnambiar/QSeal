"""No machine learning or trained models are used in this module."""

from config import QBER_THRESHOLD


def exceeds_threshold(error_rate: float, threshold: float = QBER_THRESHOLD) -> bool:
	"""Return whether the observed QBER exceeds the configured fixed limit."""
	if not 0 <= error_rate <= 1:
		raise ValueError("error_rate must be between 0 and 1")
	return error_rate > threshold
