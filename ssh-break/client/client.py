#!/usr/bin/env python3
"""
client.py — the demo SSH client.

Connects to the server, performs key exchange, then gives you an interactive
shell that looks and feels like a real SSH session. The commands you type are
encrypted and sent over the wire; responses come back encrypted and are
decrypted locally before display.

Run:
    python3 client.py demo@server
    python3 client.py demo@localhost --port 2222
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from protocol import (
    BANNER_SERVER, BANNER_CLIENT,
    MSG_KEX_INIT, MSG_KEX_REPLY, MSG_KEX_DONE,
    MSG_CHANNEL, MSG_CLOSE,
    WeakDHKex, MLKEMKex,
    derive_keys, make_cipher, pack_msg, unpack_msg,
)

DEFAULT_HOST = os.environ.get("SSH_HOST", "server")
DEFAULT_PORT = int(os.environ.get("SSH_PORT", "2222"))
KEX_MODE     = os.environ.get("KEX_MODE", "weak")


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


def connect(host: str, port: int) -> None:
    algo_name = "ML-KEM-768" if KEX_MODE == "mlkem" else "Weak-DH"
    print(f"\033[90mConnecting to {host} port {port}...\033[0m")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"\033[31mssh: connect to host {host} port {port}: Connection refused\033[0m")
        sys.exit(1)

    # 1. Banner
    sock.sendall(BANNER_CLIENT)
    server_banner = b""
    while b"\r\n" not in server_banner:
        server_banner += sock.recv(1)

    # 2. Key exchange
    if KEX_MODE == "mlkem":
        kex = MLKEMKex()
        dk, ek, init_wire = kex.client_init()
    else:
        kex = WeakDHKex()
        _, init_wire = kex.client_init()

    sock.sendall(init_wire)

    msg_type, reply_payload = recv_packet(sock)
    assert msg_type == MSG_KEX_REPLY

    if KEX_MODE == "mlkem":
        ss, session_id = kex.client_finish(reply_payload, dk)
    else:
        ss, session_id = kex.client_finish(reply_payload)

    # Consume KEX_DONE
    recv_packet(sock)

    # 3. Session keys
    c2s_key, s2c_key = derive_keys(ss)
    encrypt_cipher = make_cipher(c2s_key)
    decrypt_cipher = make_cipher(s2c_key)

    print(f"\033[90mAuthenticated to {host} ({algo_name}).\033[0m")
    print(f"\033[90mWarning: Permanently added '{host}' to the list of known hosts.\033[0m")
    print()

    # 4. Interactive session
    while True:
        try:
            cmd = input("demo@server:~$ ")
        except (EOFError, KeyboardInterrupt):
            cmd = "exit"

        # Strip any stray control characters (from terminal escape sequences)
        cmd = "".join(c for c in cmd if ord(c) >= 32 or c in "\t").strip()
        if not cmd:
            continue

        enc_cmd = encrypt_cipher.encrypt(cmd.encode())
        sock.sendall(pack_msg(MSG_CHANNEL, enc_cmd))

        if cmd.strip() == "exit":
            sock.sendall(pack_msg(MSG_CLOSE, b""))
            print("\033[90mConnection to server closed.\033[0m")
            break

        msg_type, enc_resp = recv_packet(sock)
        if msg_type == MSG_CLOSE:
            print("\033[90mConnection closed by remote host.\033[0m")
            break

        response = decrypt_cipher.decrypt(enc_resp).decode("utf-8", "replace")
        print(response, end="" if response.endswith("\n") else "\n")

    sock.close()


def main() -> None:
    args = sys.argv[1:]
    host, port = DEFAULT_HOST, DEFAULT_PORT

    for arg in args:
        if "@" in arg:
            host = arg.split("@")[1]
        elif arg.isdigit():
            port = int(arg)
        elif arg.startswith("--port="):
            port = int(arg.split("=")[1])

    connect(host, port)


if __name__ == "__main__":
    main()
