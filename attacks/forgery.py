"""Fabricated-signature attack using guessed qubit states."""

import numpy as np

from protocol.signer import SignaturePackage


def forge(message: bytes, session_id: int = 1, seed: int = 0) -> SignaturePackage:
	"""Create random eigenstates without performing a genuine teleportation."""
	generator = np.random.default_rng(seed)
	bases = [generator.choice(["X", "Y", "Z"]) for _ in range(len(message) * 8)]
	states = []
	for _ in bases:
		angle = generator.uniform(0, 2 * np.pi)
		states.append(np.array([np.cos(angle / 2), np.exp(1j * angle) * np.sin(angle / 2)]))
	return SignaturePackage(states, bases, [(0, 0)] * len(states), session_id, len(message), "unknown")
