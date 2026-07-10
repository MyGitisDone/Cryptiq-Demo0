"""
app.py — the attacker dashboard (port 8000).

Watches both banks' harvested wire traffic (and, if Wireshark's tshark is
installed, shows real packets flowing on loopback). When someone signs in to the
Bad Insecure Bank, it factors the tiny RSA modulus with Shor, decrypts the login,
and pops the stolen credentials. One click then drains that account.

Run:  uvicorn app:app --port 8000
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import random
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

import channel
from shor import run_shor
from quantum_sampler import get_sampler
from sniffer import LiveSniffer, available as tshark_available

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
BAD_URL = os.environ.get("BAD_URL", "http://127.0.0.1:8001")
GOOD_URL = os.environ.get("GOOD_URL", "http://127.0.0.1:8002")
IFACE = os.environ.get("SNIFF_IFACE", "lo0")
MAX_FACTOR_N = 100_000

app = FastAPI(title="Q-DAY — attacker dashboard")
_client_factory = None
_packet_q: "queue.Queue" = queue.Queue()
_sniffer = None


def client(url: str, target: str) -> httpx.AsyncClient:
    if _client_factory:
        return _client_factory(target)
    return httpx.AsyncClient(base_url=url, timeout=15)


def _crack(entry: dict) -> dict:
    N, e = int(entry["N"]), entry["e"]
    result = run_shor(N, get_sampler(), shots=512)
    if not result.success or not result.factors:
        return {"ok": False}
    p, q = result.factors
    d = pow(e, -1, (p - 1) * (q - 1))
    session_key = pow(int(entry["wrapped_key"]), d, N)
    plaintext = channel.open_sealed(session_key, entry["payload_hex"]).decode("utf-8", "replace")
    fields = dict(kv.split("=", 1) for kv in plaintext.split("&") if "=" in kv)
    return {"ok": True, "factors": [p, q], "username": fields.get("username"),
            "password": fields.get("password"), "mode": entry["mode"]}


@app.get("/api/status")
def status():
    # Bank links always point at localhost, never the LAN IP: the browser's
    # Web Crypto API (crypto.subtle, used by channel.js) only works in a
    # "secure context" — https, or http://127.0.0.1 / http://localhost.
    # Opening a bank over the LAN address makes crypto.subtle undefined and
    # sign-up/sign-in fails with a cryptic "Cannot read properties of
    # undefined (reading 'digest')" error.
    def force_localhost(url: str) -> str:
        import re
        return re.sub(r"://[^:/]+", "://127.0.0.1", url)

    return {"tshark": tshark_available(), "iface": IFACE,
            "banks": {"bad": force_localhost(BAD_URL), "good": force_localhost(GOOD_URL)}}


@app.get("/api/feed")
async def feed():
    global _sniffer
    if tshark_available() and _sniffer is None:
        _sniffer = LiveSniffer(IFACE, (8001, 8002))
        _sniffer.start(lambda pkt: _packet_q.put(pkt))

    async def gen():
        def ev(e, **d): return f"data: {json.dumps({'event': e, **d})}\n\n"
        yield ev("listening", tshark=tshark_available(), iface=IFACE)
        seen: set = set()
        while True:
            drained = 0
            while not _packet_q.empty() and drained < 20:
                pkt = _packet_q.get()
                bank = "bad" if 8001 in (pkt["src_port"], pkt["dst_port"]) else "good"
                yield ev("packet", bank=bank, **pkt)
                drained += 1

            for target, url in (("bad", BAD_URL), ("good", GOOD_URL)):
                try:
                    async with client(url, target) as http:
                        cap = (await http.get("/capture")).json().get("capture", [])
                except Exception:
                    continue
                for entry in cap:
                    key_material = entry.get("wrapped_key") or entry.get("kem_ct_b64", "")
                    kid = (target, entry["ts"], key_material)
                    if kid in seen:
                        continue
                    seen.add(kid)
                    material_preview = str(key_material)[:24]
                    yield ev("wire", bank=target, mode=entry["mode"], tiny=entry["tiny"],
                             bits=entry["bits"], wrapped_key=material_preview,
                             payload_preview=entry["payload_hex"][:32] + "…")
                    if entry["tiny"] and int(entry["N"]) <= MAX_FACTOR_N:
                        res = await asyncio.to_thread(_crack, entry)
                        if res.get("ok"):
                            yield ev("cracked", bank=target, mode=res["mode"],
                                     factors=res["factors"], username=res["username"],
                                     password=res["password"],
                                     rsa_N=entry["N"], rsa_e=entry["e"],
                                     wrapped_key=entry["wrapped_key"],
                                     payload_hex=entry["payload_hex"])
                    else:
                        yield ev("safe", bank=target, bits=entry["bits"],
                                 algorithm=entry.get("algorithm", "unknown"))
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class DrainIn(BaseModel):
    bank: str = "bad"
    username: str
    password: str


ATTACKER_WALLET = 0   # in-memory running total the attacker has stolen this session


@app.get("/api/wallet")
def wallet():
    return {"balance": ATTACKER_WALLET}


@app.post("/api/drain")
async def drain(req: DrainIn):
    global ATTACKER_WALLET
    url = BAD_URL if req.bank == "bad" else GOOD_URL
    target = "bad" if req.bank == "bad" else "good"
    async with client(url, target) as http:
        cfg = (await http.get("/api/config")).json()
        if not cfg["key"]["tiny"]:
            return {"ok": False, "error": "This bank uses ML-KEM — there's no stolen "
                                          "session key to replay a login with."}
        N, e = int(cfg["key"]["N"]), cfg["key"]["e"]
        s = random.randrange(2, min(N, 2 ** 240))
        wrapped = pow(s, e, N)
        payload_hex = channel.seal(s, f"username={req.username}&password={req.password}".encode())
        auth = (await http.post("/api/auth", json={
            "mode": "signin", "wrapped_key": str(wrapped), "payload_hex": payload_hex})).json()
        if not auth.get("ok"):
            return {"ok": False, "error": auth.get("error", "sign-in failed")}
        tr = (await http.post("/api/transfer", json={"token": auth["token"], "to": "attacker-wallet"})).json()
        if tr.get("ok"):
            ATTACKER_WALLET += tr.get("moved", 0)
        return {"ok": tr.get("ok", False), "error": tr.get("error"), "moved": tr.get("moved"),
                "victim_balance": tr.get("balance"), "wallet_balance": ATTACKER_WALLET}


@app.get("/")
def index():
    return FileResponse(FRONTEND / "dashboard.html")


@app.get("/dashboard.css")
def css():
    return FileResponse(FRONTEND / "dashboard.css")


@app.get("/dashboard.js")
def js():
    return FileResponse(FRONTEND / "dashboard.js")
