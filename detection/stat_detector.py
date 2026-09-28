"""
stat_detector.py

Turns raw measurement statistics into an accept/reject decision. This
is the "cyber threat detection" layer sitting on top of the quantum
protocol -- no AI/ML anywhere in this file, as the problem statement
requires.

Two detection modes are provided:

  detect()             single-basis threshold test (fast, but has the
                        ~50% blind spot documented in main.py)
  detect_dual_basis()  combines a Z-basis and an X-basis measurement
                        of the SAME signature; rejects if EITHER basis
                        shows a statistically significant deviation.
                        This is the recommended mode for the platform.

SECURITY ANALYSIS -- forgery probability and multi-round signing:
Even dual-basis detection cannot catch an attacker who, by pure luck,
guesses BOTH correction bits correctly: that is indistinguishable
from a genuine signature, because it IS (numerically) the same
transformation. For a single qubit/round, that happens with
probability 1/4 (2 random bits, 4 equally likely combinations).

The mitigation used in real QDS proposals -- and implemented here via
`forgery_acceptance_probability()` / `required_rounds_for_security()`
-- is to sign across N independent rounds (N separate Bell pairs) and
require ALL rounds to pass verification. An attacker must then guess
correctly in every round simultaneously, so their success probability
drops to (1/4)^N: exponentially small with only a handful of rounds.
"""

import math
from dataclasses import dataclass


@dataclass
class DetectionResult:
    verdict: str            # "ACCEPT" or "REJECT"
    deviation: float        # |measured - expected|
    z_score: float          # deviation in units of expected shot noise
    forgery_probability: float   # heuristic 0..1 confidence it's an attack


@dataclass
class DualBasisResult:
    verdict: str
    z_basis: DetectionResult
    x_basis: DetectionResult


def _shot_noise_stddev(p: float, shots: int) -> float:
    """Standard binomial shot-noise standard deviation for a
    population estimate p over N shots."""
    return math.sqrt(p * (1 - p) / shots) if 0 < p < 1 else 1 / math.sqrt(shots)


def detect(expected_p1: float, measured_p1: float, shots: int, z_threshold: float = 4.0) -> DetectionResult:
    """
    Flags a signature as forged/tampered if its measured population
    deviates from the expected population by more than `z_threshold`
    standard deviations of shot noise.

    z_threshold=4.0 is deliberately conservative (roughly a 1-in-16,000
    false-positive rate under normal shot noise) so that legitimate
    signatures are not spuriously rejected -- tune this against your
    own benchmark run counts before presenting results.
    """
    deviation = abs(measured_p1 - expected_p1)
    sigma = _shot_noise_stddev(expected_p1, shots)
    z = deviation / sigma if sigma > 0 else float("inf")

    forgery_probability = min(1.0, z / (z_threshold * 2))
    verdict = "REJECT" if z > z_threshold else "ACCEPT"
    return DetectionResult(verdict=verdict, deviation=deviation, z_score=z,
                            forgery_probability=forgery_probability)


def detect_dual_basis(z_result: dict, x_result: dict, z_threshold: float = 4.0) -> DualBasisResult:
    """
    Combines a Z-basis and an X-basis measurement of the same
    signature. Rejects if either basis independently flags an
    anomaly -- this is what closes the single-basis blind spot (see
    module docstring): an X-type (bit-flip) mismatch shows up in the
    Z-basis result, a Z-type (phase) mismatch shows up in the X-basis
    result.
    """
    z_det = detect(z_result["expected_p1"], z_result["measured_p1"], z_result["shots"], z_threshold)
    x_det = detect(x_result["expected_p1"], x_result["measured_p1"], x_result["shots"], z_threshold)
    verdict = "REJECT" if (z_det.verdict == "REJECT" or x_det.verdict == "REJECT") else "ACCEPT"
    return DualBasisResult(verdict=verdict, z_basis=z_det, x_basis=x_det)


def forgery_acceptance_probability(rounds: int) -> float:
    """
    Probability that a blind-guessing attacker (no real entanglement)
    passes dual-basis verification across `rounds` independent
    signing rounds purely by luck. Each round has a 1/4 chance of an
    accidentally-correct guess (2 bits, 4 combinations) slipping past
    even dual-basis detection; rounds are independent, so the
    probabilities multiply.
    """
    return (1 / 4) ** rounds


def required_rounds_for_security(target_probability: float = 1e-6) -> int:
    """
    Minimum number of signing rounds needed so a blind-guessing
    attacker's success probability falls below `target_probability`.
    """
    if not (0 < target_probability < 1):
        raise ValueError("target_probability must be in (0, 1)")
    return math.ceil(math.log(target_probability) / math.log(1 / 4))


if __name__ == "__main__":
    from protocol.teleport_sign import sign_and_verify
    from attacks.attack_sim import (
        forge_or_impersonate, replay_attack, channel_manipulation,
        unauthorized_verification_attempt,
    )

    message = "release payment batch #4471"
    replay_target = "release payment batch #9999"

    def replay_both(basis):
        r = replay_attack(message, replay_target, basis=basis)
        r["expected_p1"] = r["expected_p1_new_message"]
        return r

    scenarios = {
        "Legitimate": lambda basis: sign_and_verify(message, basis=basis),
        "Forged/Impersonated": lambda basis: forge_or_impersonate(message, basis=basis),
        "Replayed": replay_both,
        "Unauthorized verification": lambda basis: unauthorized_verification_attempt(message, basis=basis),
        "Channel manipulation (20%)": lambda basis: channel_manipulation(message, flip_prob=0.2, basis=basis),
    }

    print(f"{'Scenario':<30}{'Single-basis (Z only)':<25}{'Dual-basis (Z+X)'}")
    print("-" * 80)
    for name, fn in scenarios.items():
        z_res = fn("Z")
        x_res = fn("X")
        z_only = detect(z_res["expected_p1"], z_res["measured_p1"], z_res["shots"])
        dual = detect_dual_basis(z_res, x_res)
        print(f"{name:<30}{z_only.verdict:<25}{dual.verdict}")

    print("\n--- Security analysis: forgery acceptance probability vs. rounds ---")
    for n in (1, 2, 4, 8, 16):
        p = forgery_acceptance_probability(n)
        print(f"  {n:>2} round(s): blind-guess success probability = {p:.2e}")
    print(f"\nRounds needed for < 1-in-a-million forgery acceptance: "
          f"{required_rounds_for_security(1e-6)}")
