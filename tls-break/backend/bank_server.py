"""
bank_server.py — factory that builds a bank web app. The two banks now run
genuinely different key-exchange algorithms:

  * Bad Insecure Bank  — RSA key transport, deliberately tiny modulus,
                         breakable by Shor (or brute force, at this size).
  * Good Secure Bank    — real ML-KEM-768 (FIPS 203), via kyber-py here and
                         @noble/post-quantum in the browser. Genuinely
                         quantum-safe, not "RSA but bigger."

Credential traffic (sign up / sign in) is protected with the negotiated
session key on the client, so an eavesdropper only sees ciphertext.
Everything the attacker needs to *try* to break it is exposed at /capture —
that's the harvested wire.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

import channel
from bank import Bank

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


class AuthIn(BaseModel):
    mode: str                          # "signup" | "signin"
    payload_hex: str                   # encrypted "username=..&password=.."
    wrapped_key: str | None = None     # RSA path: decimal string
    kem_ct_b64: str | None = None      # ML-KEM path: base64 ciphertext


class TokenIn(BaseModel):
    token: str


class TransferIn(BaseModel):
    token: str
    to: str = "attacker@evil.example"


class KexIn(BaseModel):
    ek_b64: str   # browser's ephemeral ML-KEM encapsulation key, base64


def make_bank_app(*, theme: str, name: str, tagline: str, store: str,
                  tiny: bool, tier: str = "instant", rsa_bits: int = 2048) -> FastAPI:
    app = FastAPI(title=name)
    bank = Bank(store, name)
    CAPTURE: list[dict] = []   # harvested wire traffic

    if tiny:
        key = channel.gen_tiny_rsa(tier)
        algorithm = "rsa"
    else:
        algorithm = "mlkem"
        key = None   # the Good bank's server holds no long-term keypair —
                     # the BROWSER generates an ephemeral ML-KEM keypair each
                     # session and sends the encapsulation key; the server
                     # only ever encapsulates against it. This matches how a
                     # real client-side-ephemeral KEM handshake works and
                     # means there's no "server private key" to steal at all.

    def public_key() -> dict:
        if tiny:
            return {"alg": "RSA (toy)", "N": str(key["N"]), "e": key["e"],
                    "bits": key["bits"], "tiny": True}
        return {"alg": "ML-KEM-768", "bits": 1184 * 8, "tiny": False}

    @app.get("/api/config")
    def config():
        return {"theme": theme, "name": name, "tagline": tagline, "key": public_key()}

    @app.get("/certificate")
    def certificate():
        """
        RSA path: the bank's public key (N, e), served before any login —
        just like a TLS certificate. Public by design; the security is
        supposed to come from factoring N being hard. For the Bad bank it
        isn't.

        ML-KEM path: there IS no persistent server certificate to publish
        here, because the Good bank's server has no long-term keypair — the
        browser generates a fresh ephemeral ML-KEM keypair every session
        (see /api/kex-init). This endpoint just explains that.
        """
        if tiny:
            return {
                "subject": name, "issuer": f"{name} Self-Signed CA", "algorithm": "RSA",
                "public_key": {"N": str(key["N"]), "e": key["e"], "bits": key["bits"]},
                "note": (f"This {key['bits']}-bit modulus is intentionally tiny. "
                        "A real RSA-2048 cert would have a 617-digit N. "
                        "Shor's algorithm breaks both — only the qubit count differs."),
            }
        return {
            "subject": name, "issuer": f"{name} Self-Signed CA", "algorithm": "ML-KEM-768",
            "public_key": None,
            "note": ("This bank has no persistent public key to publish here — the "
                     "browser generates a fresh ML-KEM-768 keypair every session and "
                     "sends the encapsulation key directly at login time. Recovering "
                     "the session's shared secret from a captured (encapsulation key, "
                     "ciphertext) pair requires breaking Module-LWE, which has no known "
                     "efficient algorithm, classical or quantum."),
        }

    @app.post("/api/auth")
    def auth(msg: AuthIn):
        if tiny:
            if msg.wrapped_key is None:
                return {"ok": False, "error": "missing wrapped_key"}
            session_key = pow(int(msg.wrapped_key), key["d"], key["N"])
            wire_extra = {"wrapped_key": msg.wrapped_key}
        else:
            if msg.kem_ct_b64 is None:
                return {"ok": False, "error": "missing kem_ct_b64"}
            # The server has no stored keypair for ML-KEM — the ciphertext in
            # msg.kem_ct_b64 was already encapsulated by the SERVER against
            # the browser's ephemeral ek in /api/kex-encaps below, and the
            # resulting shared secret was returned to the browser then. Here
            # we just need the SAME shared secret again to decrypt the login,
            # so we look it up by the ciphertext (acts as a one-time session id).
            session_key = _MLKEM_SESSIONS.pop(msg.kem_ct_b64, None)
            if session_key is None:
                return {"ok": False, "error": "unknown or expired ML-KEM session"}
            wire_extra = {"kem_ct_b64": msg.kem_ct_b64}

        try:
            payload = channel.open_sealed(session_key, msg.payload_hex).decode("utf-8", "replace")
        except Exception as exc:
            return {"ok": False, "error": f"decrypt failed: {exc}"}
        fields = dict(kv.split("=", 1) for kv in payload.split("&") if "=" in kv)
        username, password = fields.get("username", ""), fields.get("password", "")

        # Harvest the wire (this is what a sniffer records).
        CAPTURE.append({
            "ts": time.time(), "mode": msg.mode, "bank": name, "theme": theme,
            "tiny": tiny, "algorithm": algorithm,
            "N": str(key["N"]) if tiny else None, "e": key["e"] if tiny else None,
            "bits": public_key()["bits"], "payload_hex": msg.payload_hex,
            **wire_extra,
        })
        del CAPTURE[:-25]

        if msg.mode == "signup":
            return bank.signup(username, password)
        return bank.signin(username, password)

    # ── ML-KEM handshake endpoint (Good bank only) ──────────────────────
    # In-memory map: ciphertext (base64) -> shared_secret bytes, so /api/auth
    # can look up the right key without the server needing to remember a
    # per-connection session (this whole demo is stateless HTTP, no cookies
    # until after login). Entries are popped on use; a background sweep isn't
    # needed for a demo, but we cap the map size defensively.
    _MLKEM_SESSIONS: dict[str, bytes] = {}

    class KexIn(BaseModel):
        ek_b64: str   # browser's ephemeral ML-KEM encapsulation key, base64

    @app.post("/api/kex-encaps")
    def kex_encaps(msg: KexIn):
        if tiny:
            return {"ok": False, "error": "this bank uses RSA, not ML-KEM"}
        ek = base64.b64decode(msg.ek_b64)
        shared, ct = channel.mlkem_encaps(ek)
        ct_b64 = base64.b64encode(ct).decode()
        _MLKEM_SESSIONS[ct_b64] = shared
        if len(_MLKEM_SESSIONS) > 50:
            _MLKEM_SESSIONS.pop(next(iter(_MLKEM_SESSIONS)))
        return {"ok": True, "ct_b64": ct_b64}

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
