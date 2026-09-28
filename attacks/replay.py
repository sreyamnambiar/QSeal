"""Replay attack that reuses a previously accepted signature package."""

from protocol.signer import SignaturePackage, sign


def capture(message: bytes, session_id: int = 1, seed: int = 13) -> SignaturePackage:
	"""Capture one legitimate package for later replay."""
	return sign(message, session_id=session_id, seed=seed)


def replay(package: SignaturePackage) -> SignaturePackage:
	"""Return the same package unchanged, preserving its stale session id."""
	return package
