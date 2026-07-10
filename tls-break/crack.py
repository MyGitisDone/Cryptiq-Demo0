#!/usr/bin/env python3
"""
crack.py — standalone decryptor.

Takes three values visible in Wireshark and recovers the login credentials
using Shor's algorithm. No dashboard, no Qiskit, no dependencies beyond the
Python standard library.

WHERE TO GET EACH VALUE FROM WIRESHARK
---------------------------------------
Open Wireshark, capture on lo0 (macOS) / lo (Linux), filter:
    tcp.port == 8001

Then sign into the Bad Insecure Bank. You'll see two relevant HTTP exchanges:

  1. GET /certificate  → HTTP response contains N and e (the public key).
     This is sent BEFORE any login — just like a TLS certificate.
     Right-click the response → Follow → HTTP Stream. You'll see:
         {"N": "15", "e": 3, ...}

  2. POST /api/auth    → HTTP request body contains wrapped_key and payload_hex.
     Right-click → Follow → HTTP Stream. You'll see:
         {"mode":"signin","wrapped_key":"8","payload_hex":"f46a30..."}

Paste all four values below (or pass them as CLI flags), then run:
    python3 crack.py

The math:
    wrapped_key = session_key ^ e  mod N     (RSA encryption, done by the browser)
    session_key = wrapped_key ^ d  mod N     (RSA decryption, needs the private key d)
    d           = e^-1  mod (p-1)(q-1)       (only works if you know p and q)
    p, q        = factors of N               (this is what Shor's algorithm finds)
"""

import argparse
import hashlib
import json
import math
import random
import sys
import urllib.request


# ── paste your Wireshark values here ──────────────────────────────────────
# From GET /certificate response:
N = 15
e = 3
# From POST /api/auth request body:
WRAPPED = "8"
PAYLOAD = "f46a30601983363c15d4ad794eab50bf4ad8cfa329450ca35c037cfa6a404a9df8dcaccb5ddcdb99fdc8"
# ──────────────────────────────────────────────────────────────────────────


def fetch_cert(bank_url: str) -> tuple[int, int]:
    """Pull N and e directly from the bank's public certificate endpoint."""
    url = bank_url.rstrip("/") + "/certificate"
    with urllib.request.urlopen(url, timeout=5) as r:
        data = json.loads(r.read())
    pk = data["public_key"]
    return int(pk["N"]), int(pk["e"])


# ── Shor's algorithm (classical simulation, no Qiskit needed for tiny N) ──

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _find_period(a: int, N: int) -> int | None:
    """Multiplicative order of a mod N — the quantum circuit finds this on a QPU."""
    x = a % N
    for r in range(1, N + 1):
        if x == 1:
            return r
        x = (x * a) % N
    return None


def factor_shor(N: int) -> tuple[int, int] | None:
    """
    Shor's algorithm. The quantum part is period-finding (_find_period above).
    On a real quantum computer that step runs in O(log N)^3 time on a QPU;
    here we simulate it classically — fine because N is tiny.
    The dashboard uses an actual Qiskit circuit for the same step.
    """
    if N < 2:
        return None
    if N % 2 == 0:
        return 2, N // 2
    # check perfect power
    for b in range(2, N.bit_length() + 1):
        r = round(N ** (1 / b))
        for c in (r - 1, r, r + 1):
            if c > 1 and c ** b == N:
                return c, N // c

    rng = random.Random(42)
    for _ in range(64):
        a = rng.randrange(2, N)
        g = _gcd(a, N)
        if g > 1:
            return g, N // g
        r = _find_period(a, N)
        if r is None or r % 2 != 0:
            continue
        for candidate in (_gcd(pow(a, r // 2) - 1, N), _gcd(pow(a, r // 2) + 1, N)):
            if 1 < candidate < N:
                return candidate, N // candidate
    return None


# ── session-key decryption (must match channel.py / channel.js) ───────────

def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _keystream(kb: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(_sha256(kb + str(counter).encode()))
        counter += 1
    return bytes(out[:length])


def decrypt(session_key: int, payload_hex: str) -> str:
    kb = _sha256(str(session_key).encode())
    blob = bytes.fromhex(payload_hex)
    ct, tag = blob[:-8], blob[-8:]
    if _sha256(kb + b"tag" + ct)[:8] != tag:
        raise ValueError("integrity check failed — wrong session key or corrupted payload")
    ks = _keystream(kb, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks)).decode("utf-8", "replace")


# ── main ──────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Crack a captured Bad-bank login using Shor's algorithm.",
        epilog="Values come from Wireshark — see the docstring at the top of this file.",
    )
    p.add_argument("--N",           type=int, default=None, help="RSA modulus (from GET /certificate)")
    p.add_argument("--e",           type=int, default=None, help="RSA public exponent (from GET /certificate)")
    p.add_argument("--wrapped-key", type=str, default=None, dest="wrapped",
                   help="wrapped_key field from POST /api/auth body")
    p.add_argument("--payload-hex", type=str, default=None, dest="payload",
                   help="payload_hex field from POST /api/auth body")
    p.add_argument("--fetch",       type=str, default=None, metavar="BANK_URL",
                   help="Fetch N and e directly from the bank (e.g. http://127.0.0.1:8001). "
                        "Simulates what an attacker gets before any login happens.")
    args = p.parse_args()

    _N       = args.N       or N
    _e       = args.e       or e
    _wrapped = args.wrapped or WRAPPED
    _payload = args.payload or PAYLOAD

    print()
    print("══════════════════════════════════════════════════════════════")
    print("  Q-DAY standalone crack  —  independent of the dashboard")
    print("══════════════════════════════════════════════════════════════")
    print()

    # Step 0 — fetch the certificate if requested
    if args.fetch:
        print(f"  [0] Fetching public certificate from {args.fetch}/certificate")
        print(f"      (this is what Wireshark shows for GET /certificate —")
        print(f"       sent in plaintext before any login, like a TLS cert)")
        try:
            _N, _e = fetch_cert(args.fetch)
            print(f"      N = {_N}")
            print(f"      e = {_e}")
        except Exception as ex:
            print(f"      ✗  could not fetch: {ex}")
            sys.exit(1)
        print()

    # Step 1 — show what's on the wire
    hex_preview = _payload[:48] + ("…" if len(_payload) > 48 else "")
    print("  [1] Values captured from Wireshark:")
    print()
    print("      GET /certificate  →  public key (sent before any login):")
    print(f"          N = {_N}   ← RSA modulus (public)")
    print(f"          e = {_e}   ← RSA public exponent (public)")
    print()
    print("      POST /api/auth  →  encrypted login (what Wireshark sees):")
    print(f"          wrapped_key = {_wrapped}")
    print(f"                        ↑ session key encrypted under N,e  (RSA ciphertext)")
    print(f"          payload_hex = {hex_preview}")
    print(f"                        ↑ login encrypted under the session key  (unreadable)")
    print()
    print("      An attacker has all of these — the cert is public, the auth")
    print("      body is visible on the wire. The only missing piece is the")
    print("      private key d, which requires factoring N.")
    print()

    # Step 2 — factor N with Shor
    print(f"  [2] Factoring N={_N} with Shor's algorithm…")
    print(f"      (the dashboard runs this on a Qiskit quantum circuit;")
    print(f"       this script simulates the same math classically — identical result)")
    print()

    factors = factor_shor(_N)
    if not factors:
        print("      ✗  factorization failed — N might be prime or too large for this script.")
        sys.exit(1)

    p_factor, q_factor = factors
    phi = (p_factor - 1) * (q_factor - 1)
    d   = pow(_e, -1, phi)
    session_key = pow(int(_wrapped), d, _N)

    print(f"      ✔  {_N} = {p_factor} × {q_factor}")
    print(f"      private exponent  d   = e⁻¹ mod (p-1)(q-1) = {d}")
    print(f"      session key       s   = wrapped_key^d mod N = {session_key}")
    print()

    # Step 3 — decrypt
    print("  [3] Decrypting payload with recovered session key…")
    print()
    try:
        plaintext = decrypt(session_key, _payload)
    except Exception as ex:
        print(f"      ✗  {ex}")
        sys.exit(1)

    fields = dict(kv.split("=", 1) for kv in plaintext.split("&") if "=" in kv)
    print(f"      ✔  {plaintext}")
    print()
    print("  ┌──────────────────────────────────────────┐")
    print(f"  │  username : {fields.get('username', '?'):<30}│")
    print(f"  │  password : {fields.get('password', '?'):<30}│")
    print("  └──────────────────────────────────────────┘")
    print()
    print("  The payload_hex on the wire was unreadable.")
    print("  Factoring the public key with Shor made it readable.")
    print("  This works on any key where factoring N is feasible.")
    print("  RSA-2048 has a 617-digit N — not feasible today, but")
    print("  a sufficiently large quantum computer changes that.")
    print()


if __name__ == "__main__":
    main()
