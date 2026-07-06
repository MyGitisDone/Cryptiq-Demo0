"""
mlkem_demo.py — the side that survives.

ML-KEM (FIPS 203, formerly CRYSTALS-Kyber) is a lattice-based key-encapsulation
mechanism. Its security rests on the Module Learning-With-Errors problem, for
which *no* efficient quantum algorithm is known. Shor's algorithm — which
demolishes RSA and elliptic-curve crypto by finding periods / hidden subgroups
in abelian groups — has no analogue here. There is no period to find.

So this module does two things:
  1. Runs a real ML-KEM key exchange (via kyber-py).
  2. Reports, honestly, why the Shor attack that just broke RSA does not apply.
"""

from __future__ import annotations

from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

_PARAM_SETS = {
    "ML-KEM-512": (ML_KEM_512, 128),
    "ML-KEM-768": (ML_KEM_768, 192),
    "ML-KEM-1024": (ML_KEM_1024, 256),
}


@dataclass
class MLKEMExchange:
    param_set: str
    security_bits: int
    encapsulation_key_len: int
    ciphertext_len: int
    shared_secret_hex: str
    secrets_match: bool


def run_exchange(param_set: str = "ML-KEM-768") -> MLKEMExchange:
    kem, sec = _PARAM_SETS.get(param_set, _PARAM_SETS["ML-KEM-768"])

    # Alice generates a keypair and publishes the encapsulation key.
    ek, dk = kem.keygen()
    # Bob encapsulates a fresh shared secret against Alice's public key.
    shared_bob, ciphertext = kem.encaps(ek)
    # Alice decapsulates to recover the same secret.
    shared_alice = kem.decaps(dk, ciphertext)

    return MLKEMExchange(
        param_set=param_set,
        security_bits=sec,
        encapsulation_key_len=len(ek),
        ciphertext_len=len(ciphertext),
        shared_secret_hex=shared_alice.hex(),
        secrets_match=(shared_alice == shared_bob),
    )


def why_shor_fails() -> str:
    return (
        "Shor's algorithm breaks RSA and ECC by finding the period of a modular "
        "function — a hidden-subgroup problem in an abelian group. ML-KEM's "
        "security rests on Module Learning-With-Errors over lattices, which has "
        "no such periodic structure to exploit. No known quantum algorithm gives "
        "more than a small polynomial speedup, so doubling parameters keeps it "
        "safe. The circuit that just factored the RSA modulus has nothing to "
        "hook onto here."
    )
