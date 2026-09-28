"""
main.py

End-to-end demo + benchmark runner covering every deliverable in the
problem statement:
  - Scenario comparison table (legitimate + all 4 attack types),
    single-basis vs. dual-basis detection
  - Detection sensitivity vs. channel-manipulation intensity (chart)
  - Forgery-acceptance probability vs. signing rounds (chart) --
    the "forgery probability analysis" the PS explicitly asks for
  - Basic performance/complexity metrics (circuit depth, gate count,
    wall-clock time vs. shot count)

Run: python3 main.py
"""

import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from qiskit import transpile

from protocol.teleport_sign import sign_and_verify, _build_circuit, message_to_angle, SIM
from attacks.attack_sim import (
    forge_or_impersonate, replay_attack, channel_manipulation,
    unauthorized_verification_attempt,
)
from detection.stat_detector import (
    detect, detect_dual_basis, forgery_acceptance_probability,
    required_rounds_for_security,
)

MESSAGE = "release payment batch #4471"
REPLAY_TARGET = "release payment batch #9999"

OUT_DIR = Path(__file__).resolve().parent / "outputs"
OUT_DIR.mkdir(exist_ok=True)


def replay_both_bases(shots=4000):
    z = replay_attack(MESSAGE, REPLAY_TARGET, shots=shots, basis="Z")
    x = replay_attack(MESSAGE, REPLAY_TARGET, shots=shots, basis="X")
    z["expected_p1"] = z["expected_p1_new_message"]
    x["expected_p1"] = x["expected_p1_new_message"]
    return z, x


def scenario_table():
    print(f"{'Scenario':<28}{'Single-basis (Z)':<20}{'Dual-basis (Z+X)':<20}{'Z-score (Z)':<14}{'Z-score (X)'}")
    print("-" * 96)

    scenarios = [
        ("Legitimate",
         lambda: (sign_and_verify(MESSAGE, basis="Z"), sign_and_verify(MESSAGE, basis="X"))),
        ("Forgery/Impersonation",
         lambda: (forge_or_impersonate(MESSAGE, basis="Z"), forge_or_impersonate(MESSAGE, basis="X"))),
        ("Replay", lambda: replay_both_bases()),
        ("Unauthorized verification",
         lambda: (unauthorized_verification_attempt(MESSAGE, basis="Z"),
                  unauthorized_verification_attempt(MESSAGE, basis="X"))),
        ("Channel manip. (20% flip)",
         lambda: (channel_manipulation(MESSAGE, flip_prob=0.2, basis="Z"),
                  channel_manipulation(MESSAGE, flip_prob=0.2, basis="X"))),
    ]

    for name, fn in scenarios:
        z_res, x_res = fn()
        z_only = detect(z_res["expected_p1"], z_res["measured_p1"], z_res["shots"])
        dual = detect_dual_basis(z_res, x_res)
        print(f"{name:<28}{z_only.verdict:<20}{dual.verdict:<20}{z_only.z_score:<14.2f}{dual.x_basis.z_score:.2f}")


def plot_channel_manipulation_curve():
    flips = [0.0, 0.02, 0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5]
    z_scores = []
    for flip in flips:
        r = channel_manipulation(MESSAGE, flip_prob=flip, shots=3000, basis="Z")
        d = detect(r["expected_p1"], r["measured_p1"], r["shots"])
        z_scores.append(d.z_score)

    plt.figure(figsize=(7, 4.5))
    plt.plot([f * 100 for f in flips], z_scores, marker="o")
    plt.axhline(y=4.0, color="red", linestyle="--", label="Detection threshold (z=4.0)")
    plt.xlabel("Channel bit-flip probability (%)")
    plt.ylabel("Detection z-score")
    plt.title("Threat Detection Sensitivity vs. Channel Manipulation Intensity")
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT_DIR / "detection_sensitivity.png", dpi=150)
    plt.close()
    print(f"Saved chart: {OUT_DIR / 'detection_sensitivity.png'}")


def plot_forgery_probability_curve():
    rounds = list(range(1, 13))
    probs = [forgery_acceptance_probability(n) for n in rounds]

    plt.figure(figsize=(7, 4.5))
    plt.semilogy(rounds, probs, marker="o")
    plt.axhline(y=1e-6, color="red", linestyle="--", label="1-in-a-million target")
    plt.xlabel("Number of independent signing rounds")
    plt.ylabel("Blind-guess forgery acceptance probability (log scale)")
    plt.title("Forgery Probability Analysis: Multi-Round Signing")
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUT_DIR / "forgery_probability.png", dpi=150)
    plt.close()
    print(f"Saved chart: {OUT_DIR / 'forgery_probability.png'}")
    print(f"Rounds needed for <1e-6 forgery acceptance: {required_rounds_for_security(1e-6)}")


def performance_metrics():
    """
    Basic computational-complexity / performance evaluation, as the
    PS's 'benchmark ... in terms of ... computational efficiency'
    deliverable asks for.
    """
    theta = message_to_angle(MESSAGE)
    qc = _build_circuit(theta)
    tqc = transpile(qc, SIM, optimization_level=0)

    print(f"\n--- Performance / complexity metrics ---")
    print(f"Logical qubits used:      3 (fixed, independent of message length)")
    print(f"Circuit depth (transpiled): {tqc.depth()}")
    print(f"Gate count (transpiled):  {sum(tqc.count_ops().values())}  {dict(tqc.count_ops())}")

    for shots in (500, 2000, 8000):
        start = time.time()
        sign_and_verify(MESSAGE, shots=shots)
        elapsed = time.time() - start
        print(f"Wall-clock time @ {shots:>5} shots: {elapsed:.3f}s "
              f"({elapsed/shots*1000:.4f} ms/shot)")


if __name__ == "__main__":
    scenario_table()
    plot_channel_manipulation_curve()
    plot_forgery_probability_curve()
    performance_metrics()
