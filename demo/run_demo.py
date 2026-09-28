"""End-to-end command-line demonstration of QDS Threat Detection."""

from pathlib import Path

from attacks.channel_manipulation import manipulate
from attacks.forgery import forge
from attacks.impersonation import impersonate
from attacks.replay import capture, replay
from detection.decision_engine import decide
from evaluation.metrics import evaluate
from evaluation.visualize import save_reports
from protocol.signer import sign
from protocol.verifier import verify


def main() -> None:
	"""Run legitimate verification, four attacks, and evaluation reports."""
	message = b"QDS"
	print("Step 1: Legitimate sign + verify")
	legitimate = sign(message, session_id=1, seed=1)
	print(decide(verify(legitimate, message)).verdict)

	print("\nStep 2: Attack simulations")
	forged = forge(message, seed=2)
	print("Forgery:       ", decide(verify(forged, message), attack_type="forgery").verdict)
	attacker = impersonate(message, seed=3)
	print("Impersonation: ", decide(verify(attacker, message), attack_type="impersonation", key_id=attacker.key_id).verdict)
	replayed = capture(message, session_id=1, seed=4)
	print("Replay:        ", decide(verify(replay(replayed), message), attack_type="replay", session_id=1, expected_session_id=1).verdict)
	tampered = manipulate(legitimate, noise_probability=0.5, seed=5)
	print("Tampered:      ", decide(verify(tampered, message), attack_type="channel_manipulation").verdict)

	print("\nStep 3: Evaluation")
	summary = evaluate(message, trials=5)
	for name, result in summary.items():
		print(f"{name:<22} detection={result['detection_rate']:.2f} false_acceptance={result['false_acceptance_rate']:.2f}")
	paths = save_reports(summary, Path(__file__).resolve().parents[1] / "outputs")
	print("Reports:", ", ".join(str(path) for path in paths))
	print("Verification complexity: O(N) in the number of measured rounds; no exponential runtime growth.")


if __name__ == "__main__":
	main()
