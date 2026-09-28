"""
attack_sim.py

Simulates the attack types the problem statement asks for -- forgery,
impersonation, replay, unauthorized verification attempts, and
channel manipulation -- and runs each through the SAME final-
measurement pipeline as a legitimate signature (in both the Z and X
bases) so their statistics are directly comparable and no attack type
hides in the detector's blind spot.

Physical intuition behind each attack:

  FORGERY / IMPERSONATION
    An attacker without a real, shared entangled pair with the
    Verifier cannot reproduce genuine correlation. Their "signature"
    is disconnected from any real Bell measurement, so Bob's final
    qubit ends up effectively random in BOTH measurement bases. This
    is a direct consequence of the no-cloning theorem, not a
    computational assumption.

  REPLAY
    An attacker resends a previously-valid signature (classical bits
    from an old, genuine session) but pairs it with a NEW message.
    Because the correction bits were correlated with the OLD message's
    Bell measurement, applying them to a differently-encoded qubit
    produces a mismatched result -- in the Z basis if the mismatch
    involves the X-component of the correction, in the X basis if it
    involves the Z-component. Checking both bases catches all cases
    except the 1-in-4 chance the attacker's stale bits happen to
    exactly match what the new message's real correction would have
    been (an inherent limit of single-round Pauli-based signing --
    see main.py's multi-round security analysis for how this is
    mitigated).

  UNAUTHORIZED VERIFICATION ATTEMPT
    A third party (not the intended Verifier) attempts to measure/
    verify the signature qubit before the legitimate protocol
    handshake completes -- e.g. intercepting Bob's half of the Bell
    pair and measuring it prematurely. Because measurement collapses
    entanglement, this early, unauthorized measurement destroys the
    correlation the real protocol depends on: the legitimate Verifier's
    later measurement no longer matches the expected statistics either,
    so the intrusion becomes detectable retroactively.

  CHANNEL MANIPULATION
    An eavesdropper intercepts and bit-flips the qubit while it's in
    transit between Alice and Bob. Modeled with a Pauli-X noise
    channel of adjustable probability on the transit qubit -- see
    protocol/teleport_sign.py's channel_flip_prob parameter.
"""

import math

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator

from protocol.teleport_sign import message_to_angle, sign_and_verify, expected_p1, SIM


def forge_or_impersonate(message: str, shots: int = 4000, basis: str = "Z") -> dict:
    """
    Attacker has NO real entangled pair with Bob and never touches the
    real message qubit's amplitude. Without a genuine Bell-basis
    measurement outcome to work from, the best they can do is submit
    GUESSED correction bits, uniformly at random, since two truly
    independent qubits carry no information about each other.

    IMPORTANT DESIGN NOTE: it is tempting to fake this by entangling
    a decoy ancilla with the real message qubit and reading that
    instead -- but that still leaks a real Z-basis readout of the
    message and, by coincidence, reproduces roughly correct final
    statistics despite having no genuine entanglement-based security.
    That would be a modeling bug, not a real attack: a true forger has
    no channel access to the message qubit or Bob's real half at all,
    hence bits chosen independently of theta below.
    """
    theta = message_to_angle(message)

    # Bob's qubit was never entangled with the real message -- it is
    # just a fresh |0>. Batch the 4 equally-likely guessed-bit
    # combinations instead of looping shot-by-shot (each combo is
    # deterministic on |0>, so shots only matter for realistic
    # sampling proportions, not per-shot randomness).
    ones = 0
    quarter = shots // 4
    for bit_a in (0, 1):
        for bit_b in (0, 1):
            qc = QuantumCircuit(1, 1, name="forged_guess")
            if bit_b:
                qc.x(0)
            if bit_a:
                qc.z(0)
            if basis == "X":
                qc.h(0)
            qc.measure(0, 0)
            tqc = transpile(qc, SIM)
            result = SIM.run(tqc, shots=quarter).result()
            counts = result.get_counts()
            ones += counts.get("1", 0)

    p1 = ones / (quarter * 4)
    return {
        "attack": "forgery/impersonation",
        "basis": basis,
        "theta": theta,
        "expected_p1": expected_p1(theta, basis),
        "measured_p1": p1,
        "shots": shots,
    }


def replay_attack(old_message: str, new_message: str, shots: int = 4000, basis: str = "Z") -> dict:
    """
    Attacker captures a genuine signature from `old_message`'s session
    and resends it, claiming it signs `new_message` instead.

    Simulated by legitimately teleporting `old_message`'s state to get
    real correction bits from that session, then applying THOSE SAME
    bits to a freshly-encoded `new_message` qubit with no new
    entanglement -- exactly what an attacker without live channel
    access would have to do.
    """
    old_theta = message_to_angle(old_message)
    new_theta = message_to_angle(new_message)

    # Capture one genuine correction-bit pair from a real old session.
    qr = QuantumRegister(3, "q")
    cr = ClassicalRegister(3, "c")
    capture = QuantumCircuit(qr, cr, name="capture_old_signature")
    capture.ry(old_theta, 0)
    capture.h(1)
    capture.cx(1, 2)
    capture.cx(0, 1)
    capture.h(0)
    capture.measure(0, 0)
    capture.measure(1, 1)
    tcap = transpile(capture, SIM, optimization_level=0)
    cap_result = SIM.run(tcap, shots=1).result()
    outcome = list(cap_result.get_counts().keys())[0]
    bit_a, bit_b = int(outcome[-1]), int(outcome[-2])  # little-endian

    # Now replay those exact bits against the NEW message, with no
    # fresh entanglement -- this is the actual forged/replayed step.
    replay = QuantumCircuit(1, 1, name="replay_new_message")
    replay.ry(new_theta, 0)
    if bit_b:
        replay.x(0)
    if bit_a:
        replay.z(0)
    if basis == "X":
        replay.h(0)
    replay.measure(0, 0)

    tqc = transpile(replay, SIM)
    result = SIM.run(tqc, shots=shots).result()
    counts = result.get_counts()
    p1 = counts.get("1", 0) / shots

    return {
        "attack": "replay",
        "basis": basis,
        "reused_bits": (bit_a, bit_b),
        "new_theta": new_theta,
        "expected_p1_new_message": expected_p1(new_theta, basis),
        "measured_p1": p1,
        "shots": shots,
    }


def unauthorized_verification_attempt(message: str, shots: int = 4000, basis: str = "Z") -> dict:
    """
    Models a third party intercepting Bob's half of the Bell pair and
    measuring it BEFORE Alice's classical correction bits are sent --
    i.e. an unauthorized attempt to read out the signature early,
    without going through the legitimate verification handshake.

    This premature measurement collapses the entanglement early. When
    the legitimate protocol proceeds afterward (correction applied,
    then measured normally), it now operates on an already-collapsed,
    decohered qubit instead of a genuinely entangled one -- degrading
    the statistics exactly like an unwanted extra measurement/noise
    event, and making the intrusion retroactively detectable by the
    legitimate Verifier.
    """
    theta = message_to_angle(message)

    qr = QuantumRegister(3, "q")
    cr = ClassicalRegister(4, "c")   # extra classical bit for the intruder's readout
    qc = QuantumCircuit(qr, cr, name="unauthorized_verification")

    qc.ry(theta, 0)
    qc.h(1)
    qc.cx(1, 2)

    # --- Unauthorized third party measures Bob's qubit HERE, before
    # the legitimate protocol has sent/received the correction bits.
    qc.measure(2, 3)

    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, 0)
    qc.measure(1, 1)
    with qc.if_test((cr[1], 1)):
        qc.x(2)
    with qc.if_test((cr[0], 1)):
        qc.z(2)

    if basis == "X":
        qc.h(2)
    qc.measure(2, 2)

    tqc = transpile(qc, SIM, optimization_level=0)
    result = SIM.run(tqc, shots=shots).result()
    counts = result.get_counts()
    p1 = sum(v for k, v in counts.items() if k[0] == "1") / shots

    return {
        "attack": "unauthorized_verification_attempt",
        "basis": basis,
        "theta": theta,
        "expected_p1": expected_p1(theta, basis),
        "measured_p1": p1,
        "shots": shots,
    }


def channel_manipulation(message: str, flip_prob: float, shots: int = 4000, basis: str = "Z") -> dict:
    """
    Thin wrapper around the real protocol with channel_flip_prob set,
    representing an eavesdropper who intercepts and Pauli-X's the
    qubit while it's in transit.
    """
    result = sign_and_verify(message, shots=shots, channel_flip_prob=flip_prob, basis=basis)
    result["attack"] = "channel_manipulation"
    result["flip_prob"] = flip_prob
    return result


if __name__ == "__main__":
    msg = "pay $100 to Bob"
    for basis in ("Z", "X"):
        print(f"=== basis={basis} ===")
        print("Legitimate:               ", sign_and_verify(msg, basis=basis))
        print("Forgery/Impersonation:    ", forge_or_impersonate(msg, basis=basis))
        print("Replay:                   ", replay_attack(msg, "pay $9000 to Attacker", basis=basis))
        print("Unauthorized verification:", unauthorized_verification_attempt(msg, basis=basis))
        print("Channel manip. (30%):     ", channel_manipulation(msg, flip_prob=0.3, basis=basis))
        print()
