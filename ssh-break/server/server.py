#!/usr/bin/env python3
"""
server.py — the demo SSH server.

Accepts connections, performs key exchange (WeakDH or MLKEM depending on
the KEX_MODE env var), then runs an interactive command session over the
encrypted channel. All session activity is logged to stdout (the "server logs"
window in the demo).

Run:
    KEX_MODE=weak  python3 server.py   # Bad — breakable
    KEX_MODE=mlkem python3 server.py   # Good — quantum-safe
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from protocol import (
    BANNER_CLIENT, BANNER_SERVER,
    MSG_KEX_INIT, MSG_KEX_REPLY, MSG_KEX_DONE,
    MSG_CHANNEL, MSG_CLOSE,
    WeakDHKex, MLKEMKex,
    derive_keys, make_cipher, pack_msg, unpack_msg,
)

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "2222"))
KEX_MODE = os.environ.get("KEX_MODE", "weak")
DATA_DIR = Path("/demo-data")


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 4)
    length = struct.unpack(">I", header)[0]
    body = recv_exact(sock, length)
    return body[0], body[1:]


def handle_client(conn: socket.socket, addr: tuple) -> None:
    log(f"connection from {addr[0]}:{addr[1]}")
    try:
        _session(conn, addr)
    except Exception as e:
        log(f"session error: {e}")
    finally:
        conn.close()
        log(f"connection closed from {addr[0]}:{addr[1]}")


def _session(conn: socket.socket, addr: tuple) -> None:
    # 1. Banner exchange
    conn.sendall(BANNER_SERVER)
    client_banner = b""
    while b"\r\n" not in client_banner:
        client_banner += conn.recv(1)
    log(f"client banner: {client_banner.strip().decode()}")

    # 2. Key exchange
    msg_type, payload = recv_packet(conn)
    assert msg_type == MSG_KEX_INIT, f"expected KEX_INIT, got {msg_type}"

    if KEX_MODE == "mlkem":
        log("key exchange: ML-KEM-768 (quantum-safe)")
        kex = MLKEMKex()
        ss, reply_wire, session_id = kex.server_reply(payload)
    else:
        log(f"key exchange: Weak-DH (intentionally breakable)")
        kex = WeakDHKex()
        ss, reply_wire, session_id = kex.server_reply(payload)

    conn.sendall(reply_wire)
    conn.sendall(pack_msg(MSG_KEX_DONE, session_id))

    # 3. Derive session keys and set up ciphers
    c2s_key, s2c_key = derive_keys(ss)
    decrypt_cipher = make_cipher(c2s_key)
    encrypt_cipher = make_cipher(s2c_key)

    session_id_hex = session_id.hex()[:16]
    log(f"session established  id={session_id_hex}...  algo={'ML-KEM-768' if KEX_MODE=='mlkem' else 'Weak-DH'}")
    log(f"user authenticated   user=demo")
    log(f"session opened")

    # 4. Command loop
    FILES = {
        "payroll.csv": (DATA_DIR / "payroll.csv").read_text()
            if (DATA_DIR / "payroll.csv").exists()
            else "CEO,$620000\nCTO,$480000\nVP_ENG,$390000\nVP_SALES,$370000\nSR_ENG,$195000\n",
        "secrets.zip": "[binary data: 2847 bytes]",
        "readme.txt": "Confidential. Do not distribute.\n",
    }

    while True:
        msg_type, enc_payload = recv_packet(conn)
        if msg_type == MSG_CLOSE:
            log("session closed by client")
            break
        if msg_type != MSG_CHANNEL:
            continue

        # Decrypt the command — strip any stray whitespace or control chars
        cmd_bytes = decrypt_cipher.decrypt(enc_payload)
        cmd = cmd_bytes.decode("utf-8", "replace").strip().strip("\r\n")
        log(f"command: {repr(cmd)}")

        # Execute
        if cmd == "whoami":
            response = "demo\n"
        elif cmd == "hostname":
            response = "ssh-server\n"
        elif cmd == "ls":
            response = "payroll.csv  secrets.zip  readme.txt\n"
        elif cmd.startswith("cat "):
            fname = cmd[4:].strip()
            response = FILES.get(fname, f"cat: {fname}: No such file or directory\n")
        elif cmd.startswith("scp "):
            fname = cmd.split()[-2] if len(cmd.split()) > 2 else "secrets.zip"
            size = len(FILES.get(fname, "").encode())
            response = f"secrets.zip transferred ({size} bytes)\n"
        elif cmd == "exit":
            response = ""
            enc_resp = encrypt_cipher.encrypt(response.encode())
            conn.sendall(pack_msg(MSG_CHANNEL, enc_resp))
            conn.sendall(pack_msg(MSG_CLOSE, b""))
            log("session terminated normally")
            break
        else:
            response = f"{cmd}: command not found\n"

        enc_resp = encrypt_cipher.encrypt(response.encode())
        conn.sendall(pack_msg(MSG_CHANNEL, enc_resp))


def main() -> None:
    log(f"SSH-DEMO server starting  port={PORT}  kex={KEX_MODE}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    log(f"listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
