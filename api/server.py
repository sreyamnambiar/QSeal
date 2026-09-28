"""
api/server.py

FastAPI backend wrapping the QDS protocol, attacks, and detector as a
real software platform (the PS explicitly asks for "a fully
functional software platform", not a standalone script).

Run:
    pip install fastapi uvicorn
    uvicorn api.server:app --reload --port 8000

Then open http://localhost:8000/  for the dashboard, or hit the JSON
endpoints directly (see /docs for interactive Swagger UI).
"""

import base64
import hashlib
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from protocol.teleport_sign import sign_and_verify
from attacks.attack_sim import (
    forge_or_impersonate, replay_attack, channel_manipulation,
    unauthorized_verification_attempt,
)
from detection.stat_detector import (
    detect, detect_dual_basis, forgery_acceptance_probability,
    required_rounds_for_security,
)

app = FastAPI(title="Quantum-Inspired Threat Detection Platform")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class SignRequest(BaseModel):
    message: str
    shots: int = 3000


class ReplayRequest(BaseModel):
    old_message: str
    new_message: str
    shots: int = 3000


class ChannelRequest(BaseModel):
    message: str
    flip_prob: float
    shots: int = 3000


class DocumentRequest(BaseModel):
    filename: str
    content_base64: str
    expected_sha256: str
    shots: int = 3000


def _dual(fn, **kwargs) -> dict:
    """Runs `fn` in both bases and returns a combined verdict."""
    z = fn(basis="Z", **kwargs)
    x = fn(basis="X", **kwargs)
    if "expected_p1_new_message" in z:
        z["expected_p1"] = z["expected_p1_new_message"]
        x["expected_p1"] = x["expected_p1_new_message"]
    verdict = detect_dual_basis(z, x)
    return {
        "z_basis": {k: v for k, v in z.items() if k != "raw_counts"},
        "x_basis": {k: v for k, v in x.items() if k != "raw_counts"},
        "verdict": verdict.verdict,
        "z_score_z_basis": verdict.z_basis.z_score,
        "z_score_x_basis": verdict.x_basis.z_score,
    }


@app.post("/api/sign-and-verify")
def api_sign_and_verify(req: SignRequest):
    """Runs a LEGITIMATE signing + dual-basis verification session."""
    return _dual(sign_and_verify, message=req.message, shots=req.shots)


@app.post("/api/document-sign-and-verify")
def api_document_sign_and_verify(req: DocumentRequest):
    """Hashes an uploaded document, then verifies its digest as the message."""
    try:
        document_bytes = base64.b64decode(req.content_base64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("content_base64 must contain valid base64 data") from exc

    if not document_bytes:
        raise ValueError("The uploaded document is empty")
    if len(document_bytes) > 10 * 1024 * 1024:
        raise ValueError("The uploaded document must be 10 MB or smaller")

    document_hash = hashlib.sha256(document_bytes).hexdigest()
    expected_hash = req.expected_sha256.strip().lower()
    if document_hash != expected_hash:
        return {
            "filename": req.filename,
            "document_sha256": document_hash,
            "expected_sha256": expected_hash,
            "verdict": "REJECT",
            "reason": "Document hash does not match the trusted original.",
            "z_score_z_basis": 0,
            "z_score_x_basis": 0,
            "z_basis": {},
            "x_basis": {},
        }

    result = _dual(sign_and_verify, message=f"document:{document_hash}", shots=req.shots)
    return {"filename": req.filename, "document_sha256": document_hash, **result}


@app.post("/api/attack/forge")
def api_forge(req: SignRequest):
    return _dual(forge_or_impersonate, message=req.message, shots=req.shots)


@app.post("/api/attack/replay")
def api_replay(req: ReplayRequest):
    return _dual(replay_attack, old_message=req.old_message, new_message=req.new_message, shots=req.shots)


@app.post("/api/attack/unauthorized-verification")
def api_unauthorized(req: SignRequest):
    return _dual(unauthorized_verification_attempt, message=req.message, shots=req.shots)


@app.post("/api/attack/channel-manipulation")
def api_channel(req: ChannelRequest):
    return _dual(channel_manipulation, message=req.message, flip_prob=req.flip_prob, shots=req.shots)


@app.get("/api/security-analysis")
def api_security_analysis(max_rounds: int = 12, target: float = 1e-6):
    """Forgery-probability-vs-rounds curve, per the PS's explicit
    'forgery probability analysis' deliverable."""
    curve = [{"rounds": n, "forgery_probability": forgery_acceptance_probability(n)}
             for n in range(1, max_rounds + 1)]
    return {"curve": curve, "rounds_needed_for_target": required_rounds_for_security(target), "target": target}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(path) as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
