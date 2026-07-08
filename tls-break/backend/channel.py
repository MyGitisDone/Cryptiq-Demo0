"""
channel.py — session cipher + big/tiny RSA, written so the BROWSER (Web Crypto)
and Python produce identical bytes.

Wire scheme (both banks):
  1. Browser fetches the bank's RSA public key (N, e).
  2. Browser picks a session key `s` (small int for the insecure bank; 256-bit
     for the secure bank), wraps it: w = s^e mod N.
  3. Browser derives kb = SHA256(ascii(decimal(s))) and a keystream, encrypts the
     login, and POSTs {wrapped, ct_hex}.
  4. Server recovers s = w^d mod N, re-derives kb, decrypts.

An eavesdropper who records {N, e, w, ct} can only read the login if it can
factor N. Tiny N -> Shor wins. Big N -> hopeless (our stand-in for ML-KEM).
"""

from __future__ import annotations

import hashlib
import random
import secrets


# --------------------------------------------------------------------------- #
# Session cipher (must match channel.js exactly)
# --------------------------------------------------------------------------- #
def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def derive_kb(session_key: int) -> bytes:
    return _sha256(str(session_key).encode())


def _keystream(kb: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(_sha256(kb + str(counter).encode()))
        counter += 1
    return bytes(out[:length])


def seal(session_key: int, plaintext: bytes) -> str:
    kb = derive_kb(session_key)
    ks = _keystream(kb, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = _sha256(kb + b"tag" + ct)[:8]
    return (ct + tag).hex()


def open_sealed(session_key: int, hexblob: str) -> bytes:
    blob = bytes.fromhex(hexblob)
    ct, tag = blob[:-8], blob[-8:]
    kb = derive_kb(session_key)
    if _sha256(kb + b"tag" + ct)[:8] != tag:
        raise ValueError("integrity check failed (wrong session key)")
    ks = _keystream(kb, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))


# --------------------------------------------------------------------------- #
# RSA key generation (tiny for the insecure bank, big for the secure bank)
# --------------------------------------------------------------------------- #
def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def gen_rsa(bits: int, e: int = 65537) -> dict:
    """Full-size RSA keypair (used by the secure bank)."""
    half = bits // 2
    while True:
        p, q = _gen_prime(half), _gen_prime(half)
        if p == q:
            continue
        N = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        return {"N": N, "e": e, "d": d, "bits": N.bit_length()}


# tiny primes for the insecure bank, curated so Shor stays fast
TINY_PRIME_PAIRS = {"instant": [(3, 5), (5, 3)], "quick": [(3, 7), (7, 3)],
                    "slow": [(3, 17), (7, 5), (5, 7)]}


def gen_tiny_rsa(tier: str = "instant") -> dict:
    p, q = random.choice(TINY_PRIME_PAIRS.get(tier, TINY_PRIME_PAIRS["instant"]))
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while phi % e == 0:
        e += 2
    d = pow(e, -1, phi)
    return {"N": N, "e": e, "d": d, "bits": N.bit_length(), "p": p, "q": q}
