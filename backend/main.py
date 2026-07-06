"""
main.py — FastAPI backend for Q-DAY: the quantum encryption break demo.

Modes
  Solo       : you seal a secret and break it yourself.
  Two-player : a Defender seals a secret in a room; an Attacker joins with the
               room code, never sees the secret, and recovers it live. Runs on
               localhost with two browser tabs — no accounts, no database.

Endpoints
  GET  /api/config              tiers + which backends are available
  POST /api/setup               solo: seal a target, get everything back
  POST /api/room                create a two-player room -> {code}
  POST /api/room/{code}/seal    defender seals a secret into the room
  GET  /api/room/{code}         attacker fetches the public (breakable) target
  GET  /api/room/{code}/result  defender polls for the reveal
  POST /api/attack              SSE stream of Shor breaking RSA (solo or room)
  GET  /api/mlkem-attack        reports (correctly) that there's no attack
  GET  /                        serves the frontend
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import random
import secrets
import threading
import time
from pathlib import Path

# Load .env (IBM credentials) regardless of how the server is launched.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import mlkem_demo
import rsa_toy
from models import AttackRequest, SetupRequest
from quantum_backend import available_backends, get_sampler
from shor import run_shor

MAX_N = 63  # ceiling so nobody wedges the simulator with a giant modulus

app = FastAPI(title="Q-DAY — Quantum Encryption Break Demo")
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

# In-memory room store for two-player mode. {code: {...}}
ROOMS: dict[str, dict] = {}
ROOM_TTL = 60 * 30  # rooms expire after 30 minutes


# --------------------------------------------------------------------------- #
# Shared: build a target and the symmetric comparison profiles
# --------------------------------------------------------------------------- #
def _build_target(secret_message: str, tier: str, mlkem_param: str) -> dict:
    kp = rsa_toy.generate_keypair(tier)
    enc = rsa_toy.hybrid_encrypt(secret_message, kp.N, kp.e)
    exchange = mlkem_demo.run_exchange(mlkem_param)
    pw = rsa_toy.password_hash(secret_message)

    # Same row labels on both sides so the UI reads as a true comparison.
    profiles = {
        "rsa": {
            "role": "Classical vault",
            "type": "Public-key (key transport)",
            "algorithm": f"RSA (toy {kp.bits}-bit; real-world 2048-bit)",
            "hardness": "Integer factorization",
            "key_size": f"N = {kp.N} ({kp.bits}-bit)",
            "quantum_attack": "Shor's algorithm — polynomial time",
            "status": "Broken by this demo",
        },
        "mlkem": {
            "role": "Quantum-safe vault",
            "type": "Key-encapsulation mechanism (KEM)",
            "algorithm": exchange.param_set,
            "hardness": "Module Learning-With-Errors (lattices)",
            "key_size": f"{exchange.security_bits}-bit security",
            "quantum_attack": "No known efficient quantum attack",
            "status": "Holds",
        },
    }

    return {
        "public": {
            "rsa": {
                "N": kp.N, "e": kp.e, "bits": kp.bits,
                "wrapped_key": enc["wrapped_key"],
                "ciphertext": enc["payload"],
            },
            "mlkem": {
                "param_set": exchange.param_set,
                "security_bits": exchange.security_bits,
                "encapsulation_key_len": exchange.encapsulation_key_len,
                "ciphertext_len": exchange.ciphertext_len,
                "shared_secret_preview": exchange.shared_secret_hex[:16] + "…",
            },
            "hash": pw,               # at-rest; explicitly NOT the attack target
            "profiles": profiles,
        },
        "secret": {                   # server-side only, never sent to attacker
            "N": kp.N, "e": kp.e,
            "wrapped_key": enc["wrapped_key"],
            "ciphertext": enc["payload"],
            "plaintext": secret_message,
        },
    }


@app.get("/api/config")
def config():
    tiers = {
        key: {"label": cfg["label"], "N_max": cfg["N_max"]}
        for key, cfg in rsa_toy.DIFFICULTY_TIERS.items()
    }
    return {
        "tiers": tiers,
        "backends": available_backends(),
        "mlkem_params": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "max_N": MAX_N,
    }


@app.post("/api/setup")
def setup(req: SetupRequest):
    target = _build_target(req.secret_message, req.tier, req.mlkem_param)
    return target["public"] | {"mode": "solo"}


# --------------------------------------------------------------------------- #
# Two-player rooms
# --------------------------------------------------------------------------- #
class SealRequest(BaseModel):
    secret_message: str = Field(default="LAUNCH", max_length=24)
    tier: str = Field(default="instant")
    mlkem_param: str = Field(default="ML-KEM-768")


def _sweep_rooms() -> None:
    now = time.time()
    for code in [c for c, r in ROOMS.items() if now - r["created"] > ROOM_TTL]:
        ROOMS.pop(code, None)


@app.post("/api/room")
def create_room():
    _sweep_rooms()
    code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4))
    ROOMS[code] = {"created": time.time(), "sealed": False, "target": None, "result": None}
    return {"code": code}


@app.post("/api/room/{code}/seal")
def seal_room(code: str, req: SealRequest):
    room = ROOMS.get(code.upper())
    if not room:
        raise HTTPException(404, "Room not found or expired.")
    target = _build_target(req.secret_message, req.tier, req.mlkem_param)
    room["target"] = target
    room["sealed"] = True
    room["result"] = None
    return {"ok": True, "code": code.upper()}


@app.get("/api/room/{code}")
def get_room(code: str):
    room = ROOMS.get(code.upper())
    if not room:
        raise HTTPException(404, "Room not found or expired.")
    if not room["sealed"]:
        return {"sealed": False}
    return {"sealed": True} | room["target"]["public"]


@app.get("/api/room/{code}/result")
def room_result(code: str):
    room = ROOMS.get(code.upper())
    if not room:
        raise HTTPException(404, "Room not found or expired.")
    return {"result": room["result"]}


# --------------------------------------------------------------------------- #
# The attack (SSE) — works for solo params or a room code
# --------------------------------------------------------------------------- #
def _attack_worker(params: dict, room_code: str | None, q: "queue.Queue") -> None:
    def emit(event: str, **data):
        q.put({"event": event, **data})

    try:
        N = params["N"]
        if N > MAX_N:
            emit("error", message=f"N={N} exceeds the demo ceiling of {MAX_N}.")
            return

        emit("start", N=N, backend=params["backend"])
        sampler = get_sampler(params["backend"], params.get("ibm_backend_name"))

        result = run_shor(
            N, sampler, shots=params["shots"], rng=random.Random(),
            on_log=lambda msg: emit("log", message=msg),
        )

        if not result.success or result.factors is None:
            emit("failed", log=result.log)
            return

        p, q_factor = result.factors
        emit("factored", p=p, q=q_factor, order=result.order_found,
             attempts=result.attempts, shots=result.total_shots, method=result.method)

        d = rsa_toy.private_key_from_factors(p, q_factor, params["e"])
        session_key = rsa_toy.decrypt_int(params["wrapped_key"], N, d)
        recovered = rsa_toy.hybrid_decrypt(params["wrapped_key"], params["ciphertext"], N, d)
        payload = {"private_key": d, "session_key": session_key, "plaintext": recovered}
        emit("recovered", **payload)

        if room_code and room_code in ROOMS:
            ROOMS[room_code]["result"] = {"factors": [p, q_factor], **payload}
    except Exception as exc:
        emit("error", message=f"{type(exc).__name__}: {exc}")
    finally:
        q.put(None)


class RoomAttackRequest(BaseModel):
    room: str
    shots: int = Field(default=512, ge=64, le=4096)
    backend: str = Field(default="aer")
    ibm_backend_name: str | None = None


@app.post("/api/attack")
async def attack(req: dict):
    # Accept either a solo AttackRequest shape or {room, shots, backend}.
    if "room" in req:
        r = RoomAttackRequest(**req)
        room = ROOMS.get(r.room.upper())
        if not room or not room["sealed"]:
            raise HTTPException(404, "Room not sealed yet.")
        s = room["target"]["secret"]
        params = {**s, "shots": r.shots, "backend": r.backend,
                  "ibm_backend_name": r.ibm_backend_name}
        room_code = r.room.upper()
    else:
        a = AttackRequest(**req)
        params = a.model_dump()
        room_code = None

    q: "queue.Queue" = queue.Queue()
    threading.Thread(target=_attack_worker, args=(params, room_code, q), daemon=True).start()

    async def event_stream():
        while True:
            item = await asyncio.to_thread(q.get)
            if item is None:
                yield "event: done\ndata: {}\n\n"
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        event_stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/mlkem-attack")
def mlkem_attack():
    return {"broken": False, "explanation": mlkem_demo.why_shor_fails()}


# --- static frontend --------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR)), name="static")