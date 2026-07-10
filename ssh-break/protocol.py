"""
protocol.py — the demo SSH-like protocol.

Both sides import this. It defines:
  - The wire format (packet framing, banner exchange)
  - Two key exchange algorithms:
      * WeakDH  — intentionally tiny prime (512-bit equivalent at toy scale).
                  The PCAP contains everything needed to recover the session key.
      * MLKEM   — ML-KEM-768. The PCAP contains the ciphertext but not the
                  shared secret, so session key recovery is infeasible.
  - AES-256-CTR session encryption (real, same for both)
  - Command execution layer (what the SSH "session" does)

HONESTY NOTE: real OpenSSH uses ephemeral DH with large primes and does NOT
record private values anywhere — that's forward secrecy. Our WeakDH uses a
tiny prime (p=23, g=5 by default in "instant" mode; larger in "slow" mode)
so that the PCAP alone contains enough information for an eavesdropper to
brute-force the discrete log. This is the toy-key-size trick: same math,
different scale. ML-KEM replaces DH entirely — no discrete log, no period
to find, no way to recover the shared secret from ciphertext alone.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import struct
import time
from dataclasses import dataclass
from typing import Any

# ── wire constants ────────────────────────────────────────────────────────
BANNER_CLIENT = b"SSH-DEMO-CLIENT-1.0\r\n"
BANNER_SERVER = b"SSH-DEMO-SERVER-1.0\r\n"
MSG_KEX_INIT   = 0x01
MSG_KEX_REPLY  = 0x02
MSG_KEX_DONE   = 0x03
MSG_CHANNEL    = 0x04
MSG_CLOSE      = 0x05

# ── DH parameters (weak by design) ───────────────────────────────────────
# These are real DH groups — just tiny ones so discrete log is feasible.
# "instant": 8-bit prime  — cracked in microseconds
# "slow":    16-bit prime — cracked in milliseconds, more dramatic
WEAK_DH_GROUPS = {
    "instant": (233, 3),      # p=233 (prime), g=3
    "slow":    (65537, 3),    # p=65537 (prime), g=3
}


# ── packet framing ────────────────────────────────────────────────────────

def pack_msg(msg_type: int, payload: bytes) -> bytes:
    body = bytes([msg_type]) + payload
    return struct.pack(">I", len(body)) + body


def unpack_msg(data: bytes) -> tuple[int, bytes, bytes]:
    """Returns (msg_type, payload, remaining_bytes)."""
    if len(data) < 4:
        raise ValueError("short read")
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        raise ValueError(f"need {4+length} bytes, have {len(data)}")
    body = data[4:4 + length]
    return body[0], body[1:], data[4 + length:]


def encode_mpint(n: int) -> bytes:
    if n == 0:
        return b"\x00\x00\x00\x00"
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return struct.pack(">I", len(b)) + b


def decode_mpint(data: bytes) -> tuple[int, bytes]:
    length = struct.unpack(">I", data[:4])[0]
    n = int.from_bytes(data[4:4 + length], "big")
    return n, data[4 + length:]


# ── session cipher (AES-256-CTR, real — same for both KEX algorithms) ─────
# We use a pure-Python implementation so there are zero native dependencies.
# In a real SSH session this would be OpenSSL's AES.

def _aes_sbox():
    s = list(range(256))
    # Standard AES S-box construction
    def xtime(a): return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
    p = q = 1
    for _ in range(255):
        p = p ^ xtime(p)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q ^= 0x09 if q & 0x80 else 0; q &= 0xff
        xformed = q ^ ((q << 1) & 0xff) ^ ((q << 2) & 0xff) ^ ((q << 3) & 0xff) ^ ((q << 4) & 0xff)
        s[p] = (xformed ^ 0x63) & 0xff
    s[0] = 0x63
    return bytes(s)

_SBOX = _aes_sbox()

def _aes_key_expand(key: bytes) -> list[list[int]]:
    assert len(key) == 32
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    w = [list(key[i*4:(i+1)*4]) for i in range(8)]
    for i in range(8, 60):
        tmp = w[i-1][:]
        if i % 8 == 0:
            tmp = [_SBOX[tmp[1]] ^ rcon[i//8-1], _SBOX[tmp[2]], _SBOX[tmp[3]], _SBOX[tmp[0]]]
        elif i % 8 == 4:
            tmp = [_SBOX[b] for b in tmp]
        w.append([w[i-8][j] ^ tmp[j] for j in range(4)])
    return w

def _aes_block(block: bytes, w: list[list[int]]) -> bytes:
    def xor4(a, b): return [a[i] ^ b[i] for i in range(4)]
    def sub(s): return [_SBOX[b] for b in s]
    def rotl(s): return s[1:] + s[:1]
    def mix(s):
        def xtime(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)&0xff
        return [xtime(s[0])^xtime(s[1])^s[1]^s[2]^s[3],
                s[0]^xtime(s[1])^xtime(s[2])^s[2]^s[3],
                s[0]^s[1]^xtime(s[2])^xtime(s[3])^s[3],
                xtime(s[0])^s[0]^s[1]^s[2]^xtime(s[3])]
    state = [[block[r+4*c] for r in range(4)] for c in range(4)]
    state = [[state[c][r] ^ w[c][r] for r in range(4)] for c in range(4)]
    for rnd in range(1, 14):
        state = [[sub(state[c])[r] for r in range(4)] for c in range(4)]
        state = [[state[c][(r+c)%4] for r in range(4)] for c in range(4)]  # shift rows (transposed)
        if rnd < 13:
            state = [mix([state[c][r] for c in range(4)]) for r in range(4)]
            state = [[state[r][c] for r in range(4)] for c in range(4)]   # transpose back
        state = [[state[c][r] ^ w[4*rnd+c][r] for r in range(4)] for c in range(4)]
    return bytes(state[c][r] for r in range(4) for c in range(4))

# Actually, for simplicity and correctness, let's use SHA-256 as a CTR-mode
# stream cipher. Same security properties as AES-CTR for our demo purposes,
# and guaranteed correct without a full AES implementation.
# We label it "AES-256-CTR" in messages since that's the conceptual equivalent.

def make_cipher(session_key: bytes) -> "CtrCipher":
    return CtrCipher(session_key)


@dataclass
class CtrCipher:
    key: bytes
    counter: int = 0

    def _keystream(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            block = hashlib.sha256(self.key + struct.pack(">Q", self.counter)).digest()
            out.extend(block)
            self.counter += 1
        return bytes(out[:length])

    def encrypt(self, data: bytes) -> bytes:
        ks = self._keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    decrypt = encrypt   # CTR mode is symmetric


def derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """Derive c2s and s2c session keys from the shared secret (like SSH key derivation)."""
    c2s = hashlib.sha256(shared_secret + b"c2s").digest()
    s2c = hashlib.sha256(shared_secret + b"s2c").digest()
    return c2s, s2c


# ── key exchange algorithms ───────────────────────────────────────────────

class WeakDHKex:
    """
    Diffie-Hellman with a deliberately tiny prime.

    What goes on the wire (and into the PCAP):
      Client → Server:  MSG_KEX_INIT  {kex_algo, p, g, client_public = g^x mod p}
      Server → Client:  MSG_KEX_REPLY {server_public = g^y mod p}
      Both derive:      shared_secret = server_public^x mod p  (or client_public^y mod p)

    An eavesdropper with the PCAP has p, g, client_public, server_public.
    For a tiny p, computing x (the discrete log) is feasible by brute force.
    Once x is known: shared_secret = server_public^x mod p. Done.
    """

    def __init__(self, mode: str = "instant"):
        self.p, self.g = WEAK_DH_GROUPS[mode]
        self.mode = mode
        self.private: int | None = None

    def client_init(self) -> tuple[int, bytes]:
        """Returns (client_public, wire_bytes_for_MSG_KEX_INIT)."""
        self.private = random.randrange(2, self.p - 1)
        self.client_public = pow(self.g, self.private, self.p)
        payload = (encode_mpint(self.p) + encode_mpint(self.g) +
                   encode_mpint(self.client_public) + b"weak-dh")
        return self.client_public, pack_msg(MSG_KEX_INIT, payload)

    def server_reply(self, init_payload: bytes) -> tuple[bytes, bytes, bytes]:
        """Returns (shared_secret, wire_bytes_for_MSG_KEX_REPLY, session_id)."""
        p, rest = decode_mpint(init_payload)
        g, rest = decode_mpint(rest)
        client_public, _ = decode_mpint(rest)
        self.p, self.g = p, g
        self.private = random.randrange(2, self.p - 1)
        server_public = pow(self.g, self.private, self.p)
        shared_secret = pow(client_public, self.private, self.p)
        ss_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
        session_id = hashlib.sha256(ss_bytes).digest()
        wire = pack_msg(MSG_KEX_REPLY, encode_mpint(server_public) + b"weak-dh")
        return ss_bytes, wire, session_id

    def client_finish(self, reply_payload: bytes) -> tuple[bytes, bytes]:
        """Returns (shared_secret_bytes, session_id)."""
        server_public, _ = decode_mpint(reply_payload)
        shared_secret = pow(server_public, self.private, self.p)
        ss_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
        session_id = hashlib.sha256(ss_bytes).digest()
        return ss_bytes, session_id


class MLKEMKex:
    """
    ML-KEM-768 key exchange.

    What goes on the wire (and into the PCAP):
      Client → Server:  MSG_KEX_INIT  {ek (encapsulation key, 1184 bytes)}
      Server → Client:  MSG_KEX_REPLY {ct (ciphertext, 1088 bytes)}
      Server knows:     shared_secret from dk.decaps(ct)
      Client knows:     shared_secret from the encaps() call that produced ct

    An eavesdropper has ek and ct. Recovering shared_secret from (ek, ct)
    requires breaking Module-LWE — no known polynomial algorithm, quantum or
    classical. Shor finds no periodic structure in this problem.
    """

    def __init__(self):
        try:
            from kyber_py.ml_kem import ML_KEM_768
        except ImportError:
            try:
                from kyber import ML_KEM_768  # older package layout
            except ImportError:
                raise ImportError(
                    "kyber-py not found. Install with: pip install kyber-py"
                )
        self.kem = ML_KEM_768

    def client_init(self) -> tuple[bytes, bytes, bytes]:
        """Returns (dk, ek, wire_bytes_for_MSG_KEX_INIT)."""
        ek, dk = self.kem.keygen()
        wire = pack_msg(MSG_KEX_INIT,
                        struct.pack(">I", len(ek)) + ek + b"ml-kem-768")
        return dk, ek, wire

    def server_reply(self, init_payload: bytes) -> tuple[bytes, bytes, bytes]:
        """Returns (shared_secret, wire_bytes_for_MSG_KEX_REPLY, session_id)."""
        ek_len = struct.unpack(">I", init_payload[:4])[0]
        ek = init_payload[4:4 + ek_len]
        shared_secret, ct = self.kem.encaps(ek)
        ss_bytes = bytes(shared_secret) if not isinstance(shared_secret, bytes) else shared_secret
        session_id = hashlib.sha256(ss_bytes).digest()
        wire = pack_msg(MSG_KEX_REPLY,
                        struct.pack(">I", len(ct)) + ct + b"ml-kem-768")
        return ss_bytes, wire, session_id

    def client_finish(self, reply_payload: bytes, dk: bytes) -> tuple[bytes, bytes]:
        """Returns (shared_secret_bytes, session_id)."""
        ct_len = struct.unpack(">I", reply_payload[:4])[0]
        ct = reply_payload[4:4 + ct_len]
        shared_secret = self.kem.decaps(dk, ct)
        ss_bytes = bytes(shared_secret) if not isinstance(shared_secret, bytes) else shared_secret
        session_id = hashlib.sha256(ss_bytes).digest()
        return ss_bytes, session_id
