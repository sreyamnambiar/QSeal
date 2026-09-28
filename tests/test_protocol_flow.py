"""Regression test for the legitimate signer/verifier contract."""

from protocol.signer import sign
from protocol.verifier import verify


def test_legitimate_signature_verifies() -> None:
    """A deterministic seeded signature passes every projective measurement."""
    message = b"QDS"
    package = sign(message, session_id=5, seed=4)
    results = verify(package, message)
    assert len(results) == len(message) * 8
    assert all(results)