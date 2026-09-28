"""Pauli channel-manipulation attacks on teleported receiver states."""

from dataclasses import replace

import numpy as np

from protocol.signer import SignaturePackage


def manipulate(package: SignaturePackage, noise_probability: float = 0.2, seed: int = 21) -> SignaturePackage:
	"""Apply random X or Z errors to transmitted states with fixed probability."""
	if not 0 <= noise_probability <= 1:
		raise ValueError("noise_probability must be between 0 and 1")
	generator = np.random.default_rng(seed)
	states = []
	for state in package.received_states:
		changed = np.asarray(state, dtype=complex).copy()
		if generator.random() < noise_probability:
			if generator.integers(0, 2):
				changed = np.array([changed[1], changed[0]])
			else:
				changed[1] *= -1
		states.append(changed)
	return replace(package, received_states=states)
