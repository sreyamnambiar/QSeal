"""Statistical evaluation of legitimate and attacked verification trials."""

from collections import Counter

from attacks.channel_manipulation import manipulate
from attacks.forgery import forge
from attacks.impersonation import impersonate
from attacks.replay import capture, replay
from detection.decision_engine import decide
from protocol.signer import sign
from protocol.verifier import verify


def evaluate(message: bytes = b"QDS", trials: int = 10, channel_noise: float = 0.35) -> dict:
	"""Run fixed-count trials and report detection rates by scenario."""
	if trials < 1:
		raise ValueError("trials must be positive")
	scenarios = {"legitimate": [], "forgery": [], "impersonation": [], "replay": [], "channel_manipulation": []}
	for trial in range(trials):
		legitimate = sign(message, session_id=trial + 1, seed=trial)
		scenarios["legitimate"].append(decide(verify(legitimate, message)))

		forged = forge(message, session_id=trial + 1, seed=trial)
		scenarios["forgery"].append(decide(verify(forged, message), attack_type="forgery"))

		attacker = impersonate(message, session_id=trial + 1, seed=trial + 100)
		scenarios["impersonation"].append(decide(verify(attacker, message), key_id=attacker.key_id, attack_type="impersonation"))

		old = capture(message, session_id=trial + 1, seed=trial + 200)
		scenarios["replay"].append(decide(verify(replay(old), message), attack_type="replay", session_id=old.session_id, expected_session_id=old.session_id))

		tampered = manipulate(legitimate, noise_probability=channel_noise, seed=trial + 300)
		scenarios["channel_manipulation"].append(decide(verify(tampered, message), attack_type="channel_manipulation"))

	summary = {}
	for name, decisions in scenarios.items():
		rejected = sum(decision.verdict != "ACCEPT" for decision in decisions)
		summary[name] = {
			"trials": trials,
			"detection_rate": rejected / trials,
			"false_acceptance_rate": 1 - rejected / trials,
			"mean_error_rate": sum(decision.error_rate for decision in decisions) / trials,
			"verdicts": dict(Counter(decision.verdict for decision in decisions)),
		}
	return summary
