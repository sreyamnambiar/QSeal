"""Round-trip tests for the first quantum protocol building block."""

import numpy as np

from core.teleportation_protocol import teleport


def _assert_same_state(expected: np.ndarray, actual: np.ndarray) -> None:
	"""Compare pure states while ignoring physically irrelevant global phase."""
	fidelity = abs(np.vdot(expected, actual)) ** 2
	assert np.isclose(fidelity, 1.0, atol=1e-10)


def test_teleport_computational_basis_states() -> None:
	"""Teleportation preserves both computational-basis eigenstates."""
	for state in (np.array([1, 0]), np.array([0, 1])):
		received, classical_bits = teleport(state)
		_assert_same_state(state, received)
		assert classical_bits in {(0, 0), (0, 1), (1, 0), (1, 1)}


def test_teleport_superposition_state() -> None:
	"""The correction path also preserves relative phase for ``|+>``."""
	plus_state = np.array([1, 1], dtype=complex) / np.sqrt(2)
	received, _ = teleport(plus_state)
	_assert_same_state(plus_state, received)
