"""Message encoding and teleportation-based signing."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

import numpy as np

from core.pauli_operations import encode_bit
from core.teleportation_protocol import teleport


@dataclass
class SignaturePackage:
	"""Data sent to the verifier without storing raw encoded message bits."""

	received_states: list[np.ndarray]
	bases: list[str]
	classical_bits: list[tuple[int, int]]
	session_id: int
	message_length: int
	key_id: str = "legitimate"


def _message_bits(message: bytes) -> list[int]:
	"""Expand bytes into a deterministic most-significant-bit-first stream."""
	return [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]


def encode_message(message: bytes, seed: int | None = None) -> tuple[list[np.ndarray], list[str]]:
	"""Encode each message bit in a randomly selected Pauli eigenbasis."""
	generator = np.random.default_rng(seed) if seed is not None else secrets.SystemRandom()
	bases = [generator.choice(["X", "Y", "Z"]) for _ in _message_bits(message)]
	states = [encode_bit(bit, basis) for bit, basis in zip(_message_bits(message), bases)]
	return states, bases


def sign(message: bytes, session_id: int = 1, seed: int | None = None) -> SignaturePackage:
	"""Teleport every encoded message qubit and package verification metadata."""
	states, bases = encode_message(message, seed=seed)
	received_states = []
	classical_bits = []
	for state in states:
		received, bits = teleport(state)
		received_states.append(received)
		classical_bits.append(bits)
	return SignaturePackage(received_states, bases, classical_bits, session_id, len(message))
