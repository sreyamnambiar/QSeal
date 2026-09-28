"""Projective measurement and per-round QDS verification."""

from __future__ import annotations

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

from protocol.signer import SignaturePackage


SIMULATOR = AerSimulator()


def _message_bits(message: bytes) -> list[int]:
	"""Expand expected message bytes into verification bits."""
	return [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]


def _measure(state: np.ndarray, basis: str) -> int:
	"""Perform one Qiskit projective measurement in the disclosed basis."""
	circuit = QuantumCircuit(1, 1)
	circuit.initialize(state, 0)
	if basis == "X":
		circuit.h(0)
	elif basis == "Y":
		circuit.sdg(0)
		circuit.h(0)
	circuit.measure(0, 0)
	result = SIMULATOR.run(transpile(circuit, SIMULATOR), shots=1).result()
	return int(next(iter(result.get_counts())))


def verify(signature_package: SignaturePackage, expected_message: bytes) -> list[bool]:
	"""Measure each received state and return match/mismatch results."""
	expected_bits = _message_bits(expected_message)
	if len(expected_bits) != len(signature_package.received_states):
		raise ValueError("expected_message length does not match signature")
	return [
		_measure(state, basis) == expected_bit
		for state, basis, expected_bit in zip(
			signature_package.received_states, signature_package.bases, expected_bits
		)
	]
