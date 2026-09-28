"""
teleport_sign.py

Core teleportation-based quantum digital signature protocol.

Every "signing + verification" event is ONE quantum circuit, run for
many shots. Inside each shot:

  1. The message is encoded as a rotation angle theta on qubit 0
     (a stand-in for a message digest -> quantum state mapping).
  2. Alice and Bob share a fresh Bell pair (qubits 1 and 2).
  3. Alice performs a Bell-basis measurement on (qubit 0, qubit 1).
     The two classical bits this produces ARE the transmitted
     signature for that shot.
  4. Bob applies the Pauli correction indicated by those two bits to
     qubit 2, using Qiskit's mid-circuit classical control (if_test).
     This is real teleportation: it happens inside the circuit, using
     the actual random measurement outcome of that shot, not a value
     picked from Python.
  5. Bob measures qubit 2. Over many shots, this reconstructs the
     probability distribution of the ORIGINAL encoded message state
     -- if, and only if, every step above was genuine.

This is what makes teleportation-based signatures secure: an attacker
who does not hold a real, fresh half of the entangled pair cannot
reproduce this end-to-end statistical match, no matter what classical
bits they send (see attacks/attack_sim.py).
"""

import hashlib
import math

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, pauli_error

SIM = AerSimulator()


def message_to_angle(message: str) -> float:
    """
    Deterministically map a message to a rotation angle in [0, pi).
    Both Alice and Bob derive this the same way from the plaintext
    message (or, in a real deployment, from an agreed-upon digest),
    so no extra classical secret needs to travel alongside the
    signature bits.
    """
    digest = hashlib.sha256(message.encode()).hexdigest()
    frac = int(digest[:8], 16) / 0xFFFFFFFF
    return frac * math.pi


def _build_circuit(theta: float, verify_basis: str = "Z") -> QuantumCircuit:
    """
    Builds the full legitimate teleportation-signature circuit.

    verify_basis: "Z" (population/computational basis, catches X-type
    bit-flip mismatches) or "X" (Hadamard basis, catches Z-type phase
    mismatches). Running BOTH and combining verdicts is what closes
    the detection gap described in the module docstring below.
    """
    qr = QuantumRegister(3, "q")   # 0: message, 1: Alice's half, 2: Bob's half
    cr = ClassicalRegister(3, "c")
    qc = QuantumCircuit(qr, cr, name="qds_sign_verify")

    qc.ry(theta, 0)                 # encode the message
    qc.h(1)                         # create the shared Bell pair
    qc.cx(1, 2)
    qc.id(2)                        # channel-transit marker (attacks/noise attach here)

    qc.cx(0, 1)                     # Alice's Bell-basis measurement
    qc.h(0)
    qc.measure(0, 0)
    qc.measure(1, 1)

    with qc.if_test((cr[1], 1)):    # Bob's Pauli correction, mid-circuit,
        qc.x(2)                     # driven by THIS shot's real outcome
    with qc.if_test((cr[0], 1)):
        qc.z(2)

    if verify_basis == "X":
        qc.h(2)                     # rotate to X-basis before measuring
    qc.measure(2, 2)
    return qc


def _run_basis(theta: float, basis: str, shots: int, channel_flip_prob: float) -> dict:
    qc = _build_circuit(theta, verify_basis=basis)
    sim = SIM
    if channel_flip_prob > 0:
        noise_model = NoiseModel()
        err = pauli_error([("X", channel_flip_prob), ("I", 1 - channel_flip_prob)])
        noise_model.add_quantum_error(err, ["id"], [2])
        sim = AerSimulator(noise_model=noise_model)

    tqc = transpile(qc, sim, optimization_level=0)
    result = sim.run(tqc, shots=shots).result()
    counts = result.get_counts()
    p1 = sum(v for k, v in counts.items() if k[0] == "1") / shots
    return {"p1": p1, "raw_counts": counts}


def expected_p1(theta: float, basis: str) -> float:
    """Theoretical expected population for a legitimate signature, in
    the given basis. Z-basis: sin^2(theta/2). X-basis (measured via
    H-then-Z, where outcome '1' corresponds to the |-> eigenstate):
    (1 - sin(theta)) / 2."""
    if basis == "Z":
        return math.sin(theta / 2) ** 2
    return (1 - math.sin(theta)) / 2


def sign_and_verify(message: str, shots: int = 4000, channel_flip_prob: float = 0.0,
                     basis: str = "Z") -> dict:
    """
    Runs the full legitimate protocol `shots` times in the requested
    basis and returns the measurement statistics of Bob's final qubit.

    channel_flip_prob > 0 simulates an attacker intercepting and
    bit-flipping the qubit in transit (see attacks/attack_sim.py).
    """
    theta = message_to_angle(message)
    run = _run_basis(theta, basis, shots, channel_flip_prob)
    return {
        "theta": theta,
        "basis": basis,
        "expected_p1": expected_p1(theta, basis),
        "measured_p1": run["p1"],
        "shots": shots,
        "raw_counts": run["raw_counts"],
    }


def sign_and_verify_dual_basis(message: str, shots_per_basis: int = 2000,
                                channel_flip_prob: float = 0.0) -> dict:
    """
    Runs the protocol in BOTH the Z-basis and X-basis (using
    independent shot batches, since a single qubit can't be measured
    in two bases at once). Together these expose both an X-type
    (bit-flip) mismatch and a Z-type (phase) mismatch -- closing the
    ~50% blind spot a Z-basis-only detector has. This is the
    recommended verification mode for the actual platform.
    """
    z = sign_and_verify(message, shots=shots_per_basis, channel_flip_prob=channel_flip_prob, basis="Z")
    x = sign_and_verify(message, shots=shots_per_basis, channel_flip_prob=channel_flip_prob, basis="X")
    return {"z_basis": z, "x_basis": x}


if __name__ == "__main__":
    result = sign_and_verify("transfer $500 to account 42")
    print(f"theta            = {result['theta']:.4f}")
    print(f"expected P(1)    = {result['expected_p1']:.4f}")
    print(f"measured P(1)    = {result['measured_p1']:.4f}  <- should closely match expected")

    print("\nDual-basis run:")
    dual = sign_and_verify_dual_basis("transfer $500 to account 42")
    print("  Z-basis:", dual["z_basis"]["expected_p1"], "vs", dual["z_basis"]["measured_p1"])
    print("  X-basis:", dual["x_basis"]["expected_p1"], "vs", dual["x_basis"]["measured_p1"])
