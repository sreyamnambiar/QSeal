# Quantum-Inspired Cyber Threat Detection for Digital Signature Security

A fully functional software platform simulating a teleportation-based
Quantum Digital Signature (QDS) protocol, with a dual-basis statistical
threat-detection layer that catches forgery, impersonation, replay,
unauthorized verification, and channel-manipulation attacks — with
**no AI/ML anywhere**, as the problem statement requires.

## Why this works (in one paragraph)

Classical digital signatures rely on RSA/ECC math that quantum
computers (via Shor's algorithm) can eventually break. Teleportation-
based QDS sidesteps this by using entangled qubit pairs instead of a
computational public key. Signing = a real Bell-basis measurement
that teleports the message state; the resulting classical bits are
the signature. Verification = applying the Pauli correction and
measuring. An attacker without a genuine, fresh entangled pair cannot
reproduce the correct statistics, because of real quantum-mechanical
constraints (no-cloning), not computational hardness — that's the
information-theoretic security guarantee.

## Architecture

```
protocol/
  bell_pair.py       Bell-pair creation + entanglement sanity check
  teleport_sign.py   Full mid-circuit teleportation-based sign+verify,
                      in BOTH the Z-basis and X-basis (real physics:
                      uses Qiskit if_test for the Pauli correction,
                      driven by that shot's actual random outcome)
attacks/
  attack_sim.py      forge_or_impersonate(), replay_attack(),
                      unauthorized_verification_attempt(),
                      channel_manipulation() — each runnable in
                      either basis, producing stats directly
                      comparable to a legitimate run
detection/
  stat_detector.py   detect() (single-basis) and detect_dual_basis()
                      (combined Z+X, recommended); plus the
                      multi-round forgery-probability security model
api/
  server.py          FastAPI backend exposing every scenario as a
                      REST endpoint
  static/index.html  Browser dashboard — run signatures and attacks
                      live and see verdicts rendered in real time
main.py              Full benchmark: scenario table, sensitivity
                      chart, forgery-probability chart, performance
                      metrics
```

## Running it

**Command-line benchmark:**
```bash
pip install -r requirements.txt
python3 main.py
```
Prints a full scenario comparison table and saves two charts:
`detection_sensitivity.png` and `forgery_probability.png`.

**Live platform (the actual "software" deliverable):**
```bash
pip install -r requirements.txt
uvicorn api.server:app --reload --port 8000
```
Open `http://localhost:8000/` for the dashboard, or `http://localhost:8000/docs`
for interactive Swagger API docs. Every button in the dashboard runs a
real Qiskit Aer simulation server-side — nothing is precomputed or faked.

Individual modules can also be run standalone for isolated testing:
```bash
python3 -m protocol.bell_pair
python3 -m protocol.teleport_sign
python3 -m attacks.attack_sim
python3 -m detection.stat_detector
```

## What's genuinely demonstrated (verified against theory, not assumed)

- **Legitimate signatures**: measured population matches theory closely
  in both bases (Z: `sin²(θ/2)`, X: `(1-sin θ)/2`, for message angle θ).
- **Forgery/impersonation**: collapses to exactly 0.5 in BOTH bases —
  the physically correct signature of "no real entanglement," verified
  directly, not assumed.
- **Replay**: single-basis (Z-only) detection catches ~50% of replays;
  dual-basis detection (Z+X) empirically catches ~75% (confirmed over
  80 trials) — see Security Analysis below for how the remaining 25%
  is closed.
- **Unauthorized verification attempt**: a third party measuring Bob's
  qubit before the legitimate handshake collapses entanglement early;
  the legitimate verifier's later measurement then also shows ~0.5 in
  both bases, exactly like an outright forgery — the intrusion is
  retroactively detectable.
- **Channel manipulation**: modeled as a genuine Pauli-X noise channel
  (via Qiskit Aer's noise model); detection z-score scales smoothly
  with injected flip probability, confirmed against the theoretical
  noise-mixing formula.

## Security analysis: why dual-basis alone isn't "perfect," and the fix

A single-basis (Z-only) detector structurally misses Z-type (phase)
Pauli mismatches, since a phase-only difference is invisible to a
population measurement. **Fix implemented:** measure a second,
complementary basis (apply Hadamard before measuring — the X-basis)
and reject if *either* basis shows a significant deviation. This is
what `detect_dual_basis()` does, and it lifts replay-attack detection
from ~50% to ~75% (empirically confirmed).

The remaining gap is a fundamental limit, not an implementation bug:
an attacker who guesses **both** correction bits correctly (1-in-4
chance per round) produces a signature numerically identical to a
genuine one — no measurement can distinguish it, because it *is* the
same transformation. This is exactly the kind of "forgery probability
analysis" the problem statement asks for, and the fix is standard in
real QDS proposals: **sign across N independent rounds** (N separate
Bell pairs) and require all rounds to pass. An attacker must then
guess correctly in *every* round, so acceptance probability drops to
`(1/4)^N`:

| Rounds | Forgery acceptance probability |
|---|---|
| 1  | 25%        |
| 4  | 0.39%      |
| 8  | 0.0015%    |
| 10 | < 1 in a million |

`detection/stat_detector.py`'s `forgery_acceptance_probability()` and
`required_rounds_for_security()` compute this directly, and
`main.py` charts it (`forgery_probability.png`).

## Performance / computational complexity

- **3 logical qubits per round**, independent of message length (the
  message is hashed to a single rotation angle).
- **Circuit depth ≈ 7, gate count ≈ 11** per round after transpilation
  — this is a genuinely lightweight circuit, well within reach of
  near-term simulators and NISQ hardware, matching the PS's
  "compatible with near-term quantum hardware and simulators"
  objective.
- **~0.06–0.2 ms per shot** on the Aer simulator (measured in
  `main.py`); a full dual-basis verification with 3000 shots/basis
  completes in well under a second.
- For N-round signing (recommended for real deployment), cost scales
  linearly: N × (per-round cost) — no exponential blowup.

## Mapping to the problem statement's deliverables

| PS requirement | Where it's covered |
|---|---|
| Simulate quantum public-key distribution via Bell-state entanglement | `protocol/bell_pair.py`, `protocol/teleport_sign.py` |
| Quantum teleportation for signature transmission | `protocol/teleport_sign.py` (`_build_circuit`, mid-circuit `if_test`) |
| Pauli correction operations + projective measurement verification | `protocol/teleport_sign.py`, dual-basis in `detect_dual_basis()` |
| Detect forgery | `attacks/attack_sim.py: forge_or_impersonate()` |
| Detect impersonation | same function — modeled identically (no real entanglement access) |
| Detect replay attacks | `attacks/attack_sim.py: replay_attack()` |
| Detect unauthorized verification attempts | `attacks/attack_sim.py: unauthorized_verification_attempt()` |
| Detect quantum channel manipulation | `attacks/attack_sim.py: channel_manipulation()` (Aer noise model) |
| Pauli eigenstates, quantum measurement analysis | Z-basis and X-basis (Hadamard-rotated) measurements throughout |
| Statistical threshold methods (no AI/ML) | `detection/stat_detector.py` — pure z-score / binomial shot-noise math |
| Efficient verification maintaining information-theoretic security | Dual-basis detection + multi-round security model (no computational-hardness assumptions anywhere) |
| Forgery probability analysis | `forgery_acceptance_probability()`, `forgery_probability.png` |
| Attack simulation capabilities | `attacks/attack_sim.py`, dashboard buttons in `api/static/index.html` |
| Mathematical modelling | Inline docstrings + this README's formulas |
| Security analysis | "Security analysis" section above |
| Performance evaluation / computational efficiency | "Performance / computational complexity" section above, `main.py: performance_metrics()` |
| **A fully functional software platform** (not just a script) | `api/server.py` (FastAPI) + `api/static/index.html` (live dashboard) |
| Deterministic acceptance of legitimate signatures | Verified: legitimate runs consistently land within the z<4 acceptance band across repeated trials |

## New framework layout

The implementation also exposes the modular framework requested by the
project specification:

```text
core/          Bell preparation, teleportation, and Pauli eigenstates
protocol/      signer, verifier, and Bell-pair key distribution
attacks/       forgery, impersonation, replay, and channel manipulation
detection/     QBER statistics, fixed thresholds, probability, decisions
evaluation/    trial metrics and Matplotlib reports
demo/          end-to-end command-line runner
tests/         pytest regression suite
```

## Running the modular framework

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
python -m demo.run_demo
```

The demo prints `ACCEPT` for a legitimate signature and explicit rejection
codes for each attack. It writes `outputs/forgery_probability.png` and
`outputs/attack_detection_accuracy.png`. Verification is linear, `O(N)`, in
the number of measured rounds. Every detection module uses only fixed
thresholds, binomial error rates, and the formula `p_forge = p_round^N`;
there are no trained models or machine-learning components.

## Document integrity verification

The web dashboard also supports document verification. Select a trusted
original file and the file to verify. The backend computes a SHA-256 digest
for both files and rejects the verification when the digests differ. A file
that matches the trusted original then proceeds through the dual-basis quantum
verification flow.

This prevents a file from being accepted merely because its own newly-created
hash was verified. The result includes the document hash and an explicit
reason when integrity verification fails.

## Production deployment

The prototype is deployed on Vercel as a FastAPI Python serverless function:

- Dashboard: https://qdsproject.vercel.app/
- API documentation: https://qdsproject.vercel.app/docs

The Vercel entry point is `api/index.py`, and `vercel.json` routes both the
dashboard and REST API through the same deployment.
