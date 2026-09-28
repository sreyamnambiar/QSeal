"""
bell_pair.py

Creates and verifies the shared entangled Bell pair between the Signer
(Alice) and the Verifier (Bob). This entangled pair is the quantum
equivalent of a shared secret / public key infrastructure used in
teleportation-based Quantum Digital Signature (QDS) protocols.

Bell state used: |Phi+> = (|00> + |11>) / sqrt(2)
"""

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

SIM = AerSimulator()


def create_bell_pair_circuit() -> QuantumCircuit:
    """
    Builds a 2-qubit circuit that entangles qubit 0 (Alice's half)
    and qubit 1 (Bob's half) into the |Phi+> Bell state.

    Qubit 0 -> stays with Alice (the Signer)
    Qubit 1 -> stays with Bob   (the Verifier)
    """
    qc = QuantumCircuit(2, name="bell_pair")
    qc.h(0)
    qc.cx(0, 1)
    return qc


def verify_entanglement(shots: int = 2000) -> dict:
    """
    Sanity-check: measure both qubits of many freshly created Bell pairs.
    A correctly entangled pair should show near-perfect correlation:
    outcomes should only ever be '00' or '11', never '01' or '10'.

    Returns the raw measurement counts so you can confirm correctness
    before building the rest of the protocol on top of this.
    """
    qc = create_bell_pair_circuit()
    qc.measure_all()
    tqc = transpile(qc, SIM)
    result = SIM.run(tqc, shots=shots).result()
    return result.get_counts()


if __name__ == "__main__":
    counts = verify_entanglement()
    print("Bell pair measurement counts (should only see 00 / 11):")
    print(counts)

    only_valid = set(counts.keys()) <= {"00", "11"}
    print(f"\nEntanglement correctness check passed: {only_valid}")
