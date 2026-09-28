"""Matplotlib reports for QDS security evaluation."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from detection.forgery_probability import forgery_probability


def save_reports(summary: dict, output_dir: str | Path = "outputs", max_rounds: int = 12) -> list[Path]:
	"""Save forgery decay and attack detection charts and return their paths."""
	directory = Path(output_dir)
	directory.mkdir(parents=True, exist_ok=True)
	rounds = list(range(1, max_rounds + 1))
	probability_path = directory / "forgery_probability.png"
	plt.figure(figsize=(7, 4))
	plt.semilogy(rounds, [forgery_probability(value) for value in rounds], marker="o")
	plt.xlabel("Verification rounds")
	plt.ylabel("Forgery probability")
	plt.title("Forgery probability decays exponentially")
	plt.tight_layout()
	plt.savefig(probability_path, dpi=150)
	plt.close()

	attack_names = [name for name in summary if name != "legitimate"]
	accuracy_path = directory / "attack_detection_accuracy.png"
	plt.figure(figsize=(8, 4))
	plt.bar(attack_names, [summary[name]["detection_rate"] for name in attack_names])
	plt.ylim(0, 1.05)
	plt.ylabel("Detection rate")
	plt.title("Detection rate by attack type")
	plt.xticks(rotation=20, ha="right")
	plt.tight_layout()
	plt.savefig(accuracy_path, dpi=150)
	plt.close()
	return [probability_path, accuracy_path]
