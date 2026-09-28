"""Pauli eigenstates used by the BB84-style QDS message encoding."""

import numpy as np


PAULI_EIGENSTATES = {
	"Z": {0: np.array([1, 0], dtype=complex), 1: np.array([0, 1], dtype=complex)},
	"X": {0: np.array([1, 1], dtype=complex) / np.sqrt(2), 1: np.array([1, -1], dtype=complex) / np.sqrt(2)},
	"Y": {0: np.array([1, 1j], dtype=complex) / np.sqrt(2), 1: np.array([1, -1j], dtype=complex) / np.sqrt(2)},
}


def encode_bit(bit: int, basis: str) -> np.ndarray:
	"""Encode one classical bit as a Pauli-basis eigenstate."""
	if bit not in (0, 1) or basis not in PAULI_EIGENSTATES:
		raise ValueError("bit must be 0 or 1 and basis must be Z, X, or Y")
	return PAULI_EIGENSTATES[basis][bit].copy()


def apply_correction(state: np.ndarray, classical_bits: tuple[int, int]) -> np.ndarray:
	"""Apply teleportation's X then Z correction to a qubit state."""
	corrected = np.asarray(state, dtype=complex).copy()
	bit_zero, bit_one = classical_bits
	if bit_one:
		corrected = np.array([corrected[1], corrected[0]])
	if bit_zero:
		corrected[1] *= -1
	return corrected
