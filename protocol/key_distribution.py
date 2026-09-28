"""Bell-pair distribution for signer and verifier."""

from qiskit.quantum_info import Statevector

from core.bell_state_generator import create_bell_pair


def simulate_key_exchange(num_qubits: int) -> list[dict]:
	"""Generate ``num_qubits`` fresh Bell pairs and distribute their halves."""
	if num_qubits < 1:
		raise ValueError("num_qubits must be positive")
	pairs = []
	for index in range(num_qubits):
		circuit, statevector = create_bell_pair()
		pairs.append({
			"index": index,
			"circuit": circuit,
			"shared_state": Statevector(statevector),
			"signer_half": 0,
			"verifier_half": 1,
		})
	return pairs
