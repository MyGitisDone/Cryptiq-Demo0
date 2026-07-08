"""
bank_server.py — factory that builds a bank web app. Both banks are the same
code with different key strength and branding:

  * Bad Insecure Bank  — tiny RSA modulus (breakable by Shor)
  * Good Secure Bank    — full-size RSA modulus (stands in for ML-KEM: the demo
                          keeps a real quantum-safe KEM in the companion
                          dashboard, and uses an unbreakable-at-scale key here so
                          the point lands without shipping a browser KEM library)

Credential traffic (sign up / sign in) is wrapped with the bank's public key on
the client, so an eavesdropper only sees ciphertext. Everything the attacker
needs to *try* to break it is exposed at /capture — that's the harvested wire.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

import channel
from bank import Bank

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


class AuthIn(BaseModel):
    mode: str                 # "signup" | "signin"
    wrapped_key: str          # decimal string (may be huge)
    payload_hex: str          # encrypted "username=..&password=.."


class TokenIn(BaseModel):
    token: str


class TransferIn(BaseModel):
    token: str
    to: str = "attacker@evil.example"


def make_bank_app(*, theme: str, name: str, tagline: str, store: str,
                  tiny: bool, tier: str = "instant", rsa_bits: int = 2048) -> FastAPI:
    app = FastAPI(title=name)
    bank = Bank(store, name)
    key = channel.gen_tiny_rsa(tier) if tiny else channel.gen_rsa(rsa_bits)
    CAPTURE: list[dict] = []   # harvested credential traffic (what's on the wire)

    def public_key() -> dict:
        return {"alg": "RSA (toy)" if tiny else f"RSA-{key['bits']} (ML-KEM in production)",
                "N": str(key["N"]), "e": key["e"], "bits": key["bits"], "tiny": tiny}

    @app.get("/api/config")
    def config():
        return {"theme": theme, "name": name, "tagline": tagline, "key": public_key()}

    @app.get("/certificate")
    def certificate():
        """
        The bank's public key — served before any login, just like a TLS
        certificate in a real handshake. An eavesdropper watching the wire
        gets this for free. N and e are PUBLIC — that's what 'public key' means.
        The security comes from the fact that factoring N should be hard.
        For the Bad bank it isn't.
        """
        return {
            "subject":    name,
            "issuer":     f"{name} Self-Signed CA",
            "algorithm":  "RSA",
            "public_key": {
                "N": str(key["N"]),
                "e": key["e"],
                "bits": key["bits"],
            },
            "note": (
                f"This {key['bits']}-bit modulus is intentionally tiny. "
                "A real RSA-2048 cert would have a 617-digit N. "
                "Shor's algorithm breaks both — only the qubit count differs."
            ) if tiny else (
                f"This {key['bits']}-bit modulus is full-size. "
                "Shor's algorithm would need a fault-tolerant quantum computer "
                "with millions of logical qubits to break it."
            ),
        }

    @app.post("/api/auth")
    def auth(msg: AuthIn):
        session_key = pow(int(msg.wrapped_key), key["d"], key["N"])
        try:
            payload = channel.open_sealed(session_key, msg.payload_hex).decode("utf-8", "replace")
        except Exception as exc:
            return {"ok": False, "error": f"decrypt failed: {exc}"}
        fields = dict(kv.split("=", 1) for kv in payload.split("&") if "=" in kv)
        username, password = fields.get("username", ""), fields.get("password", "")

        # Harvest the wire (this is what a sniffer records).
        CAPTURE.append({
            "ts": time.time(), "mode": msg.mode, "bank": name, "theme": theme,
            "N": str(key["N"]), "e": key["e"], "bits": key["bits"], "tiny": tiny,
            "wrapped_key": msg.wrapped_key, "payload_hex": msg.payload_hex,
        })
        del CAPTURE[:-25]

        if msg.mode == "signup":
            return bank.signup(username, password)
        return bank.signin(username, password)

    @app.post("/api/account")
    def account(msg: TokenIn):
        return bank.account(msg.token)

    @app.post("/api/transfer")
    def transfer(msg: TransferIn):
        return bank.transfer_out(msg.token, to=msg.to)

    @app.get("/capture")
    def capture():
        return {"capture": CAPTURE}

    @app.get("/")
    def index():
        return FileResponse(FRONTEND / "bank.html")

    @app.get("/bank.css")
    def css():
        return FileResponse(FRONTEND / "bank.css")

    @app.get("/bank.js")
    def js():
        return FileResponse(FRONTEND / "bank.js")

    @app.get("/channel.js")
    def cjs():
        return FileResponse(FRONTEND / "channel.js")

    return app
