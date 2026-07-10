"""
channel.py — session cipher + key exchange, written so the BROWSER and
Python produce identical bytes.

Wire scheme:
  Bad Insecure Bank  — RSA key transport with a deliberately tiny modulus.
    1. Browser fetches (N, e).
    2. Browser picks a session key `s`, wraps it: w = s^e mod N.
    3. Browser derives kb = SHA256(ascii(decimal(s))), encrypts the login.
    4. Server recovers s = w^d mod N.
    An eavesdropper with {N, e, w, ct} can read the login only if it can
    factor N — tiny N means Shor (or even brute force) wins.

  Good Secure Bank  — real ML-KEM-768 (FIPS 203), same algorithm as the
    Python side of the SSH demo, via kyber-py on the server and
    @noble/post-quantum in the browser.
    1. Browser generates an ML-KEM keypair (ek, dk) fresh per session,
       fetches nothing from the server for this step — it's the browser's
       own ephemeral key, matching how a real client-authenticated KEM
       exchange would work.
    2. Browser sends ek to the server.
    3. Server encapsulates against ek: (shared_secret, ct) = encaps(ek).
    4. Server sends ct back; browser decapsulates: shared_secret = decaps(dk, ct).
    5. Both derive kb = SHA256(shared_secret_bytes) and encrypt the same way.
    An eavesdropper with {ek, ct} cannot recover shared_secret — that
    requires breaking Module-LWE, which has no known classical or quantum
    shortcut. This is genuinely quantum-safe, not "RSA but bigger."
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


def derive_kb(session_key) -> bytes:
    """session_key is either an int (RSA path) or raw bytes (ML-KEM shared
    secret) — both sides must agree on which, and both branches are simple
    enough to keep in one function rather than forcing every caller to know
    which key-exchange algorithm produced the key."""
    if isinstance(session_key, (bytes, bytearray)):
        return _sha256(bytes(session_key))
    return _sha256(str(session_key).encode())


def _keystream(kb: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(_sha256(kb + str(counter).encode()))
        counter += 1
    return bytes(out[:length])


def seal(session_key, plaintext: bytes) -> str:
    kb = derive_kb(session_key)
    ks = _keystream(kb, len(plaintext))
    ct = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = _sha256(kb + b"tag" + ct)[:8]
    return (ct + tag).hex()


def open_sealed(session_key, hexblob: str) -> bytes:
    blob = bytes.fromhex(hexblob)
    ct, tag = blob[:-8], blob[-8:]
    kb = derive_kb(session_key)
    if _sha256(kb + b"tag" + ct)[:8] != tag:
        raise ValueError("integrity check failed (wrong session key)")
    ks = _keystream(kb, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))


# --------------------------------------------------------------------------- #
# RSA key generation (tiny for the insecure bank only)
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
    """Full-size RSA keypair. No longer used by the Good bank (which is now
    real ML-KEM) — kept for anyone who wants a 'big but still classical,
    still quantum-breakable' comparison point."""
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


# --------------------------------------------------------------------------- #
# ML-KEM-768 (FIPS 203) — real post-quantum key exchange for the Good bank
# --------------------------------------------------------------------------- #
def _ml_kem():
    try:
        from kyber_py.ml_kem import ML_KEM_768
    except ImportError:
        from kyber import ML_KEM_768  # older package layout, just in case
    return ML_KEM_768


def mlkem_encaps(ek: bytes) -> tuple[bytes, bytes]:
    """Server side: given the browser's ephemeral encapsulation key, produce
    (shared_secret, ciphertext). The ciphertext goes back to the browser;
    the shared_secret never leaves the server."""
    kem = _ml_kem()
    shared, ct = kem.encaps(ek)
    return bytes(shared), bytes(ct)
