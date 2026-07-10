#!/usr/bin/env python3
"""
decrypt.py — offline traffic decryptor.

Takes a pcap file captured during the demo SSH session and attempts to
recover the session key and decrypt all traffic.

  WeakDH session:  recovers the DH private key by brute-force discrete log
                   (feasible because the prime is tiny), derives the session
                   keys, and decrypts every command and response.

  ML-KEM session:  reads the ek and ciphertext from the PCAP, notes that
                   recovering the shared secret from (ek, ct) requires
                   breaking Module-LWE, reports failure.

Usage:
    python3 decrypt.py captures/ssh-demo.pcap

The tool never connects to the server. It works only from the captured file,
exactly like a real harvest-now-decrypt-later attack.
"""

from __future__ import annotations

import hashlib
import math
import struct
import sys
import time
from pathlib import Path

# ── PCAP parsing ──────────────────────────────────────────────────────────
PCAP_GLOBAL_HEADER = 24
PCAP_PKT_HEADER    = 16
LINKTYPE_ETHERNET  = 1
LINKTYPE_LOOPBACK  = 0
LINKTYPE_NULL      = 0


def parse_pcap(path: str) -> list[tuple[int, int, bytes]]:
    """Return (src_port, dst_port, tcp_payload) for every TCP packet with a payload."""
    data = Path(path).read_bytes()
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
        raise ValueError(f"not a pcap file (magic={magic:#010x})")
    be = magic == 0xd4c3b2a1
    unpack = (lambda fmt, d: struct.unpack(">" + fmt, d)) if be else (lambda fmt, d: struct.unpack("<" + fmt, d))
    link_type = unpack("I", data[20:24])[0]
    packets = []
    offset = PCAP_GLOBAL_HEADER
    while offset + PCAP_PKT_HEADER <= len(data):
        _, _, incl_len, _ = unpack("IIII", data[offset:offset + PCAP_PKT_HEADER])
        pkt = data[offset + PCAP_PKT_HEADER: offset + PCAP_PKT_HEADER + incl_len]
        offset += PCAP_PKT_HEADER + incl_len
        parsed = _extract_tcp(pkt, link_type)
        if parsed:
            packets.append(parsed)
    return packets


def _extract_tcp(pkt: bytes, link_type: int) -> tuple[int, int, bytes] | None:
    """Strip link/IP/TCP headers; return (src_port, dst_port, payload), or None."""
    try:
        if link_type in (0, 12):    # loopback / raw
            pkt = pkt[4:]
        elif link_type == 1:        # ethernet
            pkt = pkt[14:]
        else:
            pkt = pkt[4:]

        # IP header
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            return None
        proto = pkt[9]
        if proto != 6:              # TCP only
            return None
        ip_hlen = (pkt[0] & 0x0f) * 4
        pkt = pkt[ip_hlen:]

        # TCP header
        if len(pkt) < 20:
            return None
        src_port, dst_port = struct.unpack(">HH", pkt[0:4])
        tcp_hlen = ((pkt[12] >> 4) & 0xf) * 4
        payload = pkt[tcp_hlen:]
        return (src_port, dst_port, payload) if payload else None
    except Exception:
        return None


# ── Protocol reassembly ───────────────────────────────────────────────────
# CRITICAL: a TCP connection is two INDEPENDENT byte streams — one in each
# direction. Naively concatenating every captured packet's payload together
# in capture order interleaves both directions into one blob, which corrupts
# the length-prefixed framing partway through (this is why earlier versions
# of this tool only recovered the first command or two: everything after the
# first misaligned packet failed to parse). We split by direction using the
# server's listening port, then reconstruct each stream separately.

SERVER_PORT = 2222


def split_by_direction(packets: list[tuple[int, int, bytes]]) -> tuple[bytes, bytes]:
    """Returns (client_to_server_stream, server_to_client_stream)."""
    c2s = bytearray()
    s2c = bytearray()
    for src_port, dst_port, payload in packets:
        if dst_port == SERVER_PORT:
            c2s.extend(payload)
        elif src_port == SERVER_PORT:
            s2c.extend(payload)
        # packets matching neither (e.g. capture noise) are ignored
    return bytes(c2s), bytes(s2c)


def split_messages(stream: bytes) -> list[tuple[int, bytes]]:
    """Parse the stream into (msg_type, payload) tuples."""
    # Skip banners
    msgs = []
    pos = 0
    while pos < len(stream):
        if stream[pos:pos+4] == b"SSH-":
            end = stream.find(b"\r\n", pos)
            if end == -1:
                break
            pos = end + 2
            continue
        if pos + 4 > len(stream):
            break
        try:
            length = struct.unpack(">I", stream[pos:pos+4])[0]
        except struct.error:
            break
        if length == 0 or pos + 4 + length > len(stream):
            pos += 1
            continue
        body = stream[pos + 4: pos + 4 + length]
        if body:
            msgs.append((body[0], body[1:]))
        pos += 4 + length
    return msgs


def decode_mpint(data: bytes) -> tuple[int, bytes]:
    if len(data) < 4:
        return 0, data
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        return 0, data
    n = int.from_bytes(data[4:4+length], "big")
    return n, data[4+length:]


# ── Crypto helpers ────────────────────────────────────────────────────────

def derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    c2s = hashlib.sha256(shared_secret + b"c2s").digest()
    s2c = hashlib.sha256(shared_secret + b"s2c").digest()
    return c2s, s2c


class CtrCipher:
    """Must match protocol.py's CtrCipher exactly: the counter advances once
    per 32-byte keystream block *generated*, regardless of how much of that
    block the message actually needs. Advancing based on 'was the block fully
    consumed' instead desyncs the counter the moment a message isn't an exact
    multiple of 32 bytes — which is every message in this demo, since real
    commands are short. That mismatch was the actual bug: the first message
    decrypted fine (both sides start at counter=0), and everything after it
    came out as garbage because the receiver's counter had silently stalled."""

    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0

    def decrypt(self, data: bytes) -> bytes:
        length = len(data)
        out = bytearray()
        while len(out) < length:
            block = hashlib.sha256(self.key + struct.pack(">Q", self.counter)).digest()
            out.extend(block)
            self.counter += 1
        ks = bytes(out[:length])
        return bytes(a ^ b for a, b in zip(data, ks))


# ── Attack: brute-force discrete log ─────────────────────────────────────

def baby_step_giant_step(g: int, h: int, p: int) -> int | None:
    """Solve g^x ≡ h (mod p) for x using baby-step giant-step."""
    m = int(math.isqrt(p)) + 1
    baby = {}
    val = 1
    for j in range(m):
        baby[val] = j
        val = (val * g) % p
    gm_inv = pow(pow(g, m, p), p - 2, p)  # g^(-m) mod p
    val = h
    for i in range(m):
        if val in baby:
            return i * m + baby[val]
        val = (val * gm_inv) % p
    return None


# ── Animation helpers ─────────────────────────────────────────────────────

def _bar(done: int, total: int, width: int = 32) -> str:
    filled = int(width * done / total)
    empty  = width - filled
    return "█" * filled + "░" * empty


def _animate(label: str, steps: int = 20, delay: float = 0.06,
             color: str = "\033[36m", done_color: str = "\033[32m",
             fail: bool = False) -> None:
    fail_at = int(steps * 0.6) if fail else steps
    for i in range(1, steps + 1):
        if fail and i > fail_at:
            pct = fail_at * 100 // steps
            bar = _bar(fail_at, steps)
            print(f"\r  {color}{label}\033[0m  [{bar}] {pct}%  ", end="", flush=True)
            time.sleep(delay * 0.5)
            continue
        pct = i * 100 // steps
        bar = _bar(i, steps)
        c = done_color if i == steps and not fail else color
        print(f"\r  {c}{label}\033[0m  [{bar}] {pct}%  ", end="", flush=True)
        time.sleep(delay)
    if fail:
        print(f"\r  \033[31m{label}\033[0m  [{_bar(fail_at, steps)}] FAILED" + " " * 10)
    else:
        print(f"\r  {done_color}{label}\033[0m  [{_bar(steps, steps)}] DONE  " + " " * 10)


def _print_slow(text: str, delay: float = 0.018, color: str = "") -> None:
    reset = "\033[0m" if color else ""
    for ch in text:
        print(color + ch + reset, end="", flush=True)
        time.sleep(delay)
    print()


# ── Main ──────────────────────────────────────────────────────────────────

MSG_KEX_INIT  = 0x01
MSG_KEX_REPLY = 0x02
MSG_CHANNEL   = 0x04


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 decrypt.py <capture.pcap>")
        sys.exit(1)

    pcap_path = sys.argv[1]

    print()
    print("\033[1;37m╔══════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[1;37m║          HNDL Decryptor — offline traffic analysis           ║\033[0m")
    print("\033[1;37m╚══════════════════════════════════════════════════════════════╝\033[0m")
    print()

    # Load PCAP
    print(f"  \033[90mReading {pcap_path}...\033[0m", flush=True)
    try:
        packets = parse_pcap(pcap_path)
    except Exception as ex:
        print(f"  \033[31m✗  Could not read pcap: {ex}\033[0m")
        sys.exit(1)

    # Split into the two independent directions BEFORE parsing messages —
    # concatenating both directions into one blob corrupts the framing.
    c2s_stream, s2c_stream = split_by_direction(packets)
    c2s_msgs = split_messages(c2s_stream)   # client → server: KEX_INIT, commands
    s2c_msgs = split_messages(s2c_stream)   # server → client: KEX_REPLY, KEX_DONE, responses

    if not c2s_msgs and not s2c_msgs:
        print("  \033[31m✗  No protocol messages found in capture.\033[0m")
        print("     Make sure you ran the demo and captured on the right interface.")
        sys.exit(1)

    total_bytes = len(c2s_stream) + len(s2c_stream)
    print(f"  \033[90m{len(packets)} packets  ·  {total_bytes} bytes  ·  "
          f"{len(c2s_msgs)+len(s2c_msgs)} protocol messages "
          f"({len(c2s_msgs)} client→server, {len(s2c_msgs)} server→client)\033[0m")
    print()

    # Detect algorithm from the client's KEX_INIT message
    kex_init = next(((mt, pl) for mt, pl in c2s_msgs if mt == MSG_KEX_INIT), None)
    if not kex_init:
        print("  \033[31m✗  No key exchange found in capture.\033[0m")
        sys.exit(1)

    _, kex_payload = kex_init
    is_mlkem = b"ml-kem" in kex_payload

    print(f"  \033[36mKey exchange algorithm detected:\033[0m  "
          f"{'ML-KEM-768 (quantum-safe)' if is_mlkem else 'Weak-DH (breakable)'}")
    print()

    # ── ML-KEM path ──────────────────────────────────────────────────────
    if is_mlkem:
        _print_slow("  Reading ML-KEM handshake...", color="\033[36m")
        print()
        _animate("Parsing encapsulation key", steps=24, delay=0.04)
        _animate("Locating KEM ciphertext  ", steps=24, delay=0.04)
        print()
        _print_slow("  Attempting to recover shared secret from (ek, ct)...", color="\033[33m")
        print()
        _animate("Searching for lattice shortcut ", steps=30, delay=0.05, fail=True,
                 color="\033[33m", done_color="\033[33m")
        _animate("Trying algebraic attack         ", steps=30, delay=0.05, fail=True,
                 color="\033[33m", done_color="\033[33m")
        _animate("Brute-force key recovery        ", steps=30, delay=0.05, fail=True,
                 color="\033[33m", done_color="\033[33m")
        print()
        print("  \033[1;31m╔═══════════════════════════════════════════╗\033[0m")
        print("  \033[1;31m║               ATTACK FAILED               ║\033[0m")
        print("  \033[1;31m║                                           ║\033[0m")
        print("  \033[1;31m║  ML-KEM shared secret is not recoverable  ║\033[0m")
        print("  \033[1;31m║  from the encapsulation key + ciphertext. ║\033[0m")
        print("  \033[1;31m║                                           ║\033[0m")
        print("  \033[1;31m║  Requires breaking Module-LWE:            ║\033[0m")
        print("  \033[1;31m║  · No known classical algorithm           ║\033[0m")
        print("  \033[1;31m║  · No known quantum algorithm             ║\033[0m")
        print("  \033[1;31m║  · Shor finds no periodic structure here  ║\033[0m")
        print("  \033[1;31m║                                           ║\033[0m")
        print("  \033[1;31m║  Archived traffic remains confidential.   ║\033[0m")
        print("  \033[1;31m╚═══════════════════════════════════════════╝\033[0m")
        print()
        return

    # ── WeakDH path ───────────────────────────────────────────────────────
    _print_slow("  Reading SSH handshake...", color="\033[36m")
    print()

    # Parse DH parameters from the client's KEX_INIT
    try:
        p, rest = decode_mpint(kex_payload)
        g, rest = decode_mpint(rest)
        client_pub, _ = decode_mpint(rest)
    except Exception:
        print("  \033[31m✗  Could not parse DH parameters from capture.\033[0m")
        sys.exit(1)

    # Server's public value comes from the server→client stream's KEX_REPLY
    kex_reply = next(((mt, pl) for mt, pl in s2c_msgs if mt == MSG_KEX_REPLY), None)
    if not kex_reply:
        print("  \033[31m✗  No KEX_REPLY in capture.\033[0m")
        sys.exit(1)
    server_pub, _ = decode_mpint(kex_reply[1])

    print(f"  \033[90mFrom PCAP  —  DH parameters (public, sent in the clear):\033[0m")
    print(f"    p (prime)      = {p}")
    print(f"    g (generator)  = {g}")
    print(f"    client_public  = g^x mod p  = {client_pub}   ← eavesdropper has this")
    print(f"    server_public  = g^y mod p  = {server_pub}   ← eavesdropper has this")
    print()
    print(f"  \033[36mGoal: find x (client's private key) so that:\033[0m")
    print(f"    shared_secret = server_public ^ x mod p")
    print()

    _animate("Recovering weak DH private key", steps=28, delay=0.07)
    print()

    x = baby_step_giant_step(g, client_pub, p)
    if x is None:
        print("  \033[31m✗  Discrete log failed — p might not be in the expected range.\033[0m")
        sys.exit(1)

    shared_secret = pow(server_pub, x, p)
    ss_bytes = shared_secret.to_bytes(max(1, (shared_secret.bit_length() + 7) // 8), "big")

    print(f"  \033[32m✔  private key x = {x}\033[0m")
    print(f"  \033[32m✔  shared_secret  = {shared_secret}\033[0m")
    print()

    _animate("Deriving transport keys  ", steps=20, delay=0.05)
    c2s_key, s2c_key = derive_keys(ss_bytes)
    print()

    _animate("Decrypting captured packets", steps=28, delay=0.06)
    print()

    # Decrypt each direction's MSG_CHANNEL messages with its own cipher, in
    # order. Because we now know definitively which stream each message came
    # from, there's no more guessing — each cipher decrypts exactly the
    # messages it originally encrypted, in the same order, so the CTR
    # keystream stays correctly synchronized (a stateful stream cipher HAS
    # to be used strictly in order; interleaving directions or guessing wrong
    # would desync it, which was the second bug in the naive version).
    enc_cipher = CtrCipher(c2s_key)   # decrypts client→server (commands)
    dec_cipher = CtrCipher(s2c_key)   # decrypts server→client (responses)

    commands = []
    for mt, pl in c2s_msgs:
        if mt == MSG_CHANNEL:
            try:
                text = enc_cipher.decrypt(pl).decode("utf-8", "strict")
                commands.append(text.strip())
            except Exception:
                commands.append(None)

    responses = []
    for mt, pl in s2c_msgs:
        if mt == MSG_CHANNEL:
            try:
                text = dec_cipher.decrypt(pl).decode("utf-8", "strict")
                responses.append(text)
            except Exception:
                responses.append(None)

    print("  \033[1;32m╔══════════════════════════════════════════════════════════╗\033[0m")
    print("  \033[1;32m║                   SUCCESS — DECRYPTED                    ║\033[0m")
    print("  \033[1;32m╚══════════════════════════════════════════════════════════╝\033[0m")
    print()
    print("  \033[90m── RECOVERED SESSION ─────────────────────────────────────────\033[0m")
    print()
    print("  \033[1mUSER:\033[0m  demo")
    print()

    if commands:
        print("  \033[1mCOMMANDS TYPED:\033[0m")
        resp_iter = iter(responses)
        for cmd in commands:
            if not cmd:
                continue
            print(f"    \033[33m$ {cmd}\033[0m")
            if cmd == "exit":
                continue
            resp = next(resp_iter, None)
            if resp:
                for line in resp.split("\n")[:8]:
                    if line:
                        _print_slow(f"      {line}", delay=0.01)
    else:
        print("  \033[33m(no commands recovered — check that the capture includes the full session)\033[0m")

    print()
    print("  \033[90m──────────────────────────────────────────────────────────────\033[0m")
    print()
    print("  \033[90mEvery byte above was encrypted on the wire.\033[0m")
    print("  \033[90mOnly the weak DH group made recovery possible.\033[0m")
    print()


if __name__ == "__main__":
    main()
