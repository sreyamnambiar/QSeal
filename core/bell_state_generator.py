"""Bell-state preparation for the QDS shared entanglement resource."""

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector


def create_bell_pair() -> tuple[QuantumCircuit, Statevector]:
	"""Create ``|Phi+> = (|00> + |11>) / sqrt(2)`` and its statevector.

	A Hadamard creates an equal superposition on the signer's qubit and
	CNOT copies its computational-basis value to the verifier's qubit.
	The resulting correlations are the entanglement resource consumed by
	teleportation; no classical model is used to construct the state.
	"""
	circuit = QuantumCircuit(2, name="bell_pair")
	circuit.h(0)
	circuit.cx(0, 1)
	statevector = Statevector.from_instruction(circuit)
	return circuit, statevector


def bell_pair_probabilities() -> np.ndarray:
	"""Return the ideal basis probabilities for the prepared Bell pair."""
	_, statevector = create_bell_pair()
	return np.abs(statevector.data) ** 2
