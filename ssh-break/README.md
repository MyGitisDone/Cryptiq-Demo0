# HNDL Demo — "Harvest Now, Decrypt Later" via SSH

Two identical SSH sessions. One key exchange you can break from the packet
capture alone. One you can't. That's the entire post-quantum migration story,
shown live in four terminal windows.

---

## What the audience sees

```
+─────────────────────────+─────────────────────────+
│  Window 1: SSH Client   │  Window 2: Wireshark    │
│                         │                         │
│  $ ssh demo@server      │  TCP  SSH  SSH  SSH...  │
│  demo@server:~$ ls      │  (encrypted — nothing   │
│  demo@server:~$ cat     │   readable here)        │
│    payroll.csv          │                         │
+─────────────────────────+─────────────────────────+
│  Window 3: Decryptor    │  Window 4: Server logs  │
│                         │                         │
│  Recovering DH key...   │  [22:01] session opened │
│  ██████████  DONE       │  [22:01] cmd: whoami    │
│                         │  [22:01] cmd: cat...    │
│  SUCCESS — DECRYPTED    │  [22:02] session closed │
│  $ whoami → demo        │                         │
│  $ cat payroll.csv →    │                         │
│    CEO,$620000 ...      │                         │
+─────────────────────────+─────────────────────────+
```

**Demo 1 (classical):** the decryptor reads the pcap, recovers the DH private
key by brute-force discrete log, derives the session keys, and prints every
command and response in plaintext.

**Demo 2 (ML-KEM):** same four windows, same commands, same packet capture.
The decryptor tries the same attack and prints `ATTACK FAILED`.

---

## Quickstart

### Requirements

- Docker + Docker Compose
- Python 3.10+ (for the decryptor — runs on the host, not in Docker)
- `kyber-py` Python package: `pip install kyber-py`
- `tcpdump` (usually pre-installed on macOS/Linux)
- Wireshark (optional but great on camera)

### Demo 1 — Classical (breakable)

```bash
./scripts/run-classical.sh
```

This:
1. Builds and starts the client + server containers with `KEX_MODE=weak`
2. Starts tcpdump capturing to `captures/ssh-classical.pcap`
3. Drops you into an interactive SSH session

Type your commands (`ls`, `cat payroll.csv`, `hostname`, `exit`), then:

```bash
# Open the capture in Wireshark (optional, great for showing encrypted traffic)
wireshark captures/ssh-classical.pcap

# Decrypt it
python3 decryptor/decrypt.py captures/ssh-classical.pcap
```

### Demo 2 — ML-KEM (quantum-safe)

```bash
./scripts/run-pqc.sh
```

Same flow. Type the exact same commands. Then:

```bash
python3 decryptor/decrypt.py captures/ssh-pqc.pcap
```

Watch it fail.

---

## What changed between the two demos

Only this — in `docker-compose.yml`:

```
KEX_MODE=weak    →    KEX_MODE=mlkem
```

**Demo 1** uses Diffie-Hellman with a tiny prime (p=233). An eavesdropper
with the pcap has g, p, and both public values. Finding the private exponent
is a discrete logarithm — trivially feasible at this key size, and the exact
thing Shor's algorithm solves efficiently at any size.

**Demo 2** uses ML-KEM-768 (FIPS 203). The pcap contains the encapsulation
key (1184 bytes) and the ciphertext (1088 bytes). Recovering the shared secret
from those two values requires breaking Module-LWE. No known algorithm does
this efficiently — classical or quantum.

Everything else is identical: same AES session encryption, same commands,
same server, same packet capture tool.

---

## Running without Docker

If you'd rather not use Docker, you can run server and client directly:

```bash
pip install kyber-py

# Terminal 1 — server (classical)
KEX_MODE=weak python3 server/server.py

# Terminal 2 — client
KEX_MODE=weak SSH_HOST=localhost python3 client/client.py demo@localhost

# On host — capture (adjust interface: lo on Linux, lo0 on macOS)
tcpdump -i lo -w captures/ssh-classical.pcap 'tcp port 2222'
```

---

## Wireshark filter

```
tcp.port == 2222
```

In the packet list you'll see `SSH SSH SSH SSH` — all encrypted, no plaintext
visible. That's the "an attacker only needs this" moment. Then `decrypt.py`
pulls the plaintext out of that same capture file.

---

## Architecture

```
hndl-demo/
├── protocol.py          shared wire protocol (framing, WeakDH, ML-KEM, session cipher)
├── server/server.py     SSH-like server (handles sessions, logs commands)
├── client/client.py     SSH-like client (interactive shell, looks like real SSH)
├── decryptor/decrypt.py offline attack tool (reads pcap, animates the break)
├── demo-data/           payroll.csv and other "sensitive" files on the server
├── scripts/
│   ├── run-classical.sh full classical demo (build → capture → session)
│   └── run-pqc.sh       full PQC demo (identical flow, different KEX)
├── captures/            pcap files land here (gitignored)
├── Dockerfile           single image used by both client and server
└── docker-compose.yml   two services, KEX_MODE controls the algorithm
```

---

## Honesty note

Real SSH (OpenSSH) uses proper ephemeral DH with large primes and perfect
forward secrecy — captured traffic cannot be decrypted even with the private
key. This demo uses a tiny prime (p=233) specifically so discrete log is
feasible by brute force on a laptop. The conceptual point is identical: if the
prime were real-RSA-2048-sized, a large quantum computer running Shor's
algorithm would solve the same discrete log. ML-KEM has no discrete log
structure for Shor to exploit.

## License

MIT
