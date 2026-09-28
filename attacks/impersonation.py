"""Impersonation attack using an attacker-controlled entangled resource."""

from dataclasses import replace

from protocol.signer import sign


def impersonate(message: bytes, session_id: int = 1, seed: int = 99):
	"""Sign with an attacker's Bell pairs and mark the wrong key identity."""
	package = sign(message, session_id=session_id, seed=seed)
	return replace(package, key_id="attacker-key")
