"""Three-qubit quantum teleportation using the Qiskit Aer simulator."""

from __future__ import annotations

import numpy as np
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit_aer import AerSimulator


SIMULATOR = AerSimulator(method="statevector")


def _validate_state(state_to_send: np.ndarray) -> np.ndarray:
	"""Validate and normalize a two-amplitude pure qubit state."""
	state = np.asarray(state_to_send, dtype=complex).reshape(-1)
	if state.size != 2:
		raise ValueError("state_to_send must contain exactly two amplitudes")
	norm = np.linalg.norm(state)
	if not np.isclose(norm, 1.0):
		raise ValueError("state_to_send must be normalized")
	return state


def teleport(state_to_send: np.ndarray) -> tuple[np.ndarray, tuple[int, int]]:
	"""Teleport one arbitrary qubit and return the receiver's state.

	Qubit 0 is initialized with the input state, while qubits 1 and 2 are
	prepared as a ``|Phi+>`` Bell pair. Alice's CNOT/Hadamard Bell
	measurement produces two classical bits. Aer then applies ``X`` for
	the second bit and ``Z`` for the first bit on Bob's qubit, exactly as
	required by the teleportation identity. The returned receiver vector
	is extracted from the measured branch and is compared up to global
	phase by callers.
	"""
	state = _validate_state(state_to_send)
	quantum = QuantumRegister(3, "q")
	classical = ClassicalRegister(2, "c")
	circuit = QuantumCircuit(quantum, classical, name="teleportation")
	circuit.initialize(state, quantum[0])

	circuit.h(quantum[1])
	circuit.cx(quantum[1], quantum[2])
	circuit.cx(quantum[0], quantum[1])
	circuit.h(quantum[0])
	circuit.measure(quantum[0], classical[0])
	circuit.measure(quantum[1], classical[1])

	with circuit.if_test((classical[1], 1)):
		circuit.x(quantum[2])
	with circuit.if_test((classical[0], 1)):
		circuit.z(quantum[2])
	circuit.save_statevector()

	compiled = transpile(circuit, SIMULATOR, optimization_level=0)
	result = SIMULATOR.run(compiled, shots=1).result()
	counts = result.get_counts()
	outcome = next(iter(counts))
	bit_zero, bit_one = int(outcome[-1]), int(outcome[-2])

	full_state = np.asarray(result.data(0)["statevector"], dtype=complex)
	receiver = np.array(
		[full_state[bit_zero + 2 * bit_one], full_state[bit_zero + 2 * bit_one + 4]],
		dtype=complex,
	)
	receiver /= np.linalg.norm(receiver)
	return receiver, (bit_zero, bit_one)
