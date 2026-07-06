"""
rsa_toy.py — a deliberately tiny, real RSA implementation.

This is textbook RSA. It is real in every respect except size: the modulus N is
a product of two small primes so that Shor's algorithm (see shor.py) can factor
it on a simulator or small quantum device. The maths that recovers the private
key from the factors is *identical* to what would break RSA-2048.

DO NOT use this for anything real. It exists to be broken.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Optional

from shor import is_prime


# A menu of two-prime products, grouped by how long Shor takes on a laptop
# simulator. These are curated so the demo stays responsive.
DIFFICULTY_TIERS = {
    "instant": {"label": "Instant (~1s)", "primes": [(3, 5), (5, 3)], "N_max": 15},
    "quick":   {"label": "Quick (~10-15s)", "primes": [(3, 7), (7, 3)], "N_max": 21},
    "slow":    {"label": "Slow (~30-70s)", "primes": [(3, 17), (7, 5), (5, 7)], "N_max": 63},
}


@dataclass
class RSAKeypair:
    N: int
    e: int
    d: int
    p: int
    q: int
    bits: int

    @property
    def public(self) -> tuple[int, int]:
        return (self.N, self.e)


def _pick_primes(tier: str, rng: random.Random) -> tuple[int, int]:
    tier_cfg = DIFFICULTY_TIERS.get(tier, DIFFICULTY_TIERS["instant"])
    return rng.choice(tier_cfg["primes"])


def generate_keypair(tier: str = "instant", rng: Optional[random.Random] = None) -> RSAKeypair:
    rng = rng or random.Random()
    p, q = _pick_primes(tier, rng)
    N = p * q
    phi = (p - 1) * (q - 1)
    # Choose a public exponent coprime to phi.
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return RSAKeypair(N=N, e=e, d=d, p=p, q=q, bits=N.bit_length())


def encrypt_int(m: int, N: int, e: int) -> int:
    if not (0 <= m < N):
        raise ValueError(f"message {m} out of range for modulus {N}")
    return pow(m, e, N)


def decrypt_int(c: int, N: int, d: int) -> int:
    return pow(c, d, N)


def private_key_from_factors(p: int, q: int, e: int) -> int:
    """Reconstruct the RSA private exponent d from the recovered factors.

    This is the whole attack: once N is factored, the 'secret' key falls out.
    """
    phi = (p - 1) * (q - 1)
    return pow(e, -1, phi)


import hashlib


def _keystream(session_key: int, length: int) -> bytes:
    """Deterministic keystream expanded from the session key (demo KDF)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(f"{session_key}:{counter}".encode()).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def password_hash(text: str) -> dict:
    """Salted SHA-256 of the secret — how a password is stored *at rest*.

    Shown in the UI only as authentic texture and to teach the real lesson:
    hashing is NOT what Shor breaks. Grover gives only a quadratic speedup, so a
    256-bit hash keeps ~128-bit security post-quantum. The quantum attack in this
    demo targets the RSA key protecting data *in transit*, not this hash.
    """
    import os
    salt = os.urandom(8)
    digest = hashlib.sha256(salt + text.encode("utf-8")).hexdigest()
    return {"algorithm": "SHA-256", "salt": salt.hex(), "digest": digest}


def hybrid_encrypt(text: str, N: int, e: int, rng: Optional[random.Random] = None) -> dict:
    """Real-world shape: RSA wraps a session key; the session key encrypts data.

    This mirrors how TLS actually protects traffic, and it's why "harvest now,
    decrypt later" works: capture the RSA-wrapped key plus the symmetric
    ciphertext today, break RSA tomorrow, decrypt everything.
    """
    rng = rng or random.Random()
    session_key = rng.randrange(2, N)              # small key that fits under N
    wrapped_key = encrypt_int(session_key, N, e)   # RSA-encrypted session key
    data = text.encode("utf-8")
    ks = _keystream(session_key, len(data))
    payload = [b ^ k for b, k in zip(data, ks)]    # symmetric (XOR) ciphertext
    return {"wrapped_key": wrapped_key, "payload": payload}


def hybrid_decrypt(wrapped_key: int, payload: list[int], N: int, d: int) -> str:
    """Recover the session key via the broken RSA key, then the plaintext."""
    session_key = decrypt_int(wrapped_key, N, d)
    ks = _keystream(session_key, len(payload))
    data = bytes(c ^ k for c, k in zip(payload, ks))
    return data.decode("utf-8", errors="replace")