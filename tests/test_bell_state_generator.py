"""Tests for Bell-pair preparation."""

import numpy as np

from core.bell_state_generator import create_bell_pair


def test_create_phi_plus_bell_pair() -> None:
	"""The generator produces equal ``|00>`` and ``|11>`` amplitudes."""
	circuit, statevector = create_bell_pair()
	assert circuit.num_qubits == 2
	assert np.allclose(np.abs(statevector.data) ** 2, [0.5, 0.0, 0.0, 0.5])
