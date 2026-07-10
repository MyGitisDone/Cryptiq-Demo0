# RUNBOOK

Step-by-step instructions for running the HNDL SSH demo, testing with real
Wireshark, and troubleshooting. See `README.md` for the project overview.

---

## 1. Prerequisites

- **Docker Desktop** (macOS/Windows) or Docker Engine + Compose plugin (Linux)
- **Python 3.10+** on the host (only used to launch the demo and run the
  offline decryptor — the actual SSH client/server run inside containers)
- **Wireshark** (optional, for the standalone GUI capture)

Nothing else. `kyber-py` and `tcpdump` are installed *inside* the Docker
image automatically — you don't need them on your host.

---

## 2. Quickstart (pick your OS)

All four just call `run_demo.py`, which does the real work identically on
every platform (Docker abstracts away the OS differences for us).

**macOS / Linux**
```bash
./scripts/run-classical.sh     # Demo 1 — breakable
./scripts/run-pqc.sh           # Demo 2 — quantum-safe
```

**Windows (PowerShell)**
```powershell
.\scripts\run-classical.ps1
.\scripts\run-pqc.ps1
```

**Windows (Command Prompt)**
```
scripts\run-classical.bat
scripts\run-pqc.bat
```

**Any OS, directly**
```bash
python3 run_demo.py classical    # macOS/Linux
python run_demo.py classical     # Windows
```

Each run: builds the containers if needed, verifies `tcpdump` is present
inside the server container (auto-rebuilds without cache if it's missing —
this happens once, the first time), starts a capture *inside* the container,
drops you into an interactive SSH session, then stops the capture and copies
the `.pcap` to `captures/` on your host.

---

## 3. The demo flow

1. Run `run-classical` (or the PQC equivalent). You'll land in a prompt:
   ```
   demo@server:~$
   ```
2. Type commands:
   ```
   whoami
   ls
   cat payroll.csv
   hostname
   exit
   ```
3. On exit, the script prints where the pcap landed:
   ```
   ✔ captures/ssh-classical.pcap  (2424 bytes)
   ```
4. Decrypt it:
   ```bash
   python3 decryptor/decrypt.py captures/ssh-classical.pcap
   ```
   Classical → full session recovered, including the payroll contents.
   PQC → `ATTACK FAILED`, nothing recovered.

---

## 4. Why capture happens *inside* the container

On macOS and Windows, Docker containers run inside a hidden Linux VM
(Docker Desktop's backend) — your host's loopback interface (`lo0` / the
Windows loopback adapter) never sees container traffic at all, even though
the ports are forwarded. Capturing with `tcpdump` on the host is therefore
unreliable across platforms.

The fix: `run_demo.py` runs `tcpdump` **inside** the `ssh-server` container
(where the traffic genuinely flows, on its `eth0`), then copies the
resulting file out with `docker cp`. This works identically on macOS,
Windows, and Linux, with no `sudo` and no host firewall/permission issues.

---

## 5. Testing with real Wireshark

Two independent options:

### 5a. Open the captured file directly

After a demo run:
```bash
wireshark captures/ssh-classical.pcap
```
Filter: `tcp.port == 2222`. You'll see `SSH SSH SSH...` — all encrypted,
nothing readable. Right-click any packet → **Follow → TCP Stream** to see
the raw encrypted bytes.

### 5b. Live capture while the session runs

If you want Wireshark's live view instead of opening the file afterward,
point it at the container directly. Find the container's network namespace
interface from the host:
```bash
docker inspect ssh-server --format '{{.NetworkSettings.Networks}}'
```
This is more fiddly cross-platform (network namespaces work differently on
each OS), so for a live view during recording, the simpler and equally
convincing option is to run:
```bash
docker exec -it ssh-server tcpdump -i eth0 -n tcp
```
in a second terminal alongside the SSH session — this streams the same
`tcpdump` text output live, which reads well on camera even without the
full Wireshark GUI.

---

## 6. What changed between the two demos

Only `KEX_MODE` in `docker-compose.yml` (set automatically by which script
you run):

```
KEX_MODE=weak    →    KEX_MODE=mlkem
```

**Classical**: Diffie-Hellman with a tiny prime (`p=233`). An eavesdropper
with the pcap has `g`, `p`, and both public values — recovering the private
exponent is a discrete logarithm, trivial to brute-force at this size, and
exactly the problem Shor's algorithm solves efficiently at *any* size.

**PQC**: ML-KEM-768 (FIPS 203). The pcap contains the encapsulation key and
ciphertext. Recovering the shared secret from those requires breaking
Module-LWE — no known algorithm does this efficiently, classical or quantum.

Everything else — the session cipher, the commands, the server, the capture
method — is identical.

---

## 7. Config knobs

| Variable | Effect |
|---|---|
| `KEX_MODE` | `weak` or `mlkem` — set automatically by the run scripts |

The DH prime and ML-KEM parameter set are fixed in `protocol.py` if you want
to change them (`WEAK_DH_GROUPS` dict, or swap `ML_KEM_768` for `ML_KEM_1024`).

---

## 8. Troubleshooting

**No pcap file appears / `decrypt.py` says "No such file or directory."**
Almost always means `tcpdump` wasn't actually running when you thought it
was. `run_demo.py` verifies this itself now (`docker top ssh-server` must
show a `tcpdump` process before it lets the SSH session start) — if you're
still hitting this, check that you're on the current version of the scripts.

**`tcpdump failed to start` even though the log shows "listening on eth0."**
This was a real bug in earlier versions of this demo: the check used
`docker exec ... pgrep tcpdump`, but `pgrep` isn't installed in the
`python:3.11-slim` base image by default, so the check always failed even
when tcpdump was working. Fixed by using `docker top <container>` from the
host instead, which doesn't depend on anything being installed inside the
container. Make sure your `Dockerfile` includes `procps` in the `apt-get`
line and you've rebuilt (`docker compose build --no-cache`) if you're still
seeing this.

**Only the first command shows up when decrypting the classical pcap.**
This was a real bug in `decrypt.py`'s stream cipher — its keystream counter
only advanced when a full 32-byte block was consumed, but real commands are
almost always shorter than that, so the counter desynced from the sender
after the very first message. Fixed by matching the counter logic exactly to
`protocol.py`'s (advance once per block *generated*, not per block *fully
used*). If you're still seeing partial recovery, confirm `decryptor/decrypt.py`
has the current `CtrCipher.decrypt()` implementation.

**`docker-compose: command not found`**
Modern Docker Desktop uses `docker compose` (a space, built into the CLI)
instead of the standalone `docker-compose` binary. `run_demo.py` tries both
automatically — if you're calling `docker-compose` manually elsewhere,
switch to `docker compose`.

**Stale images after editing the Dockerfile.**
Docker aggressively caches layers. If you change the Dockerfile and things
don't seem to take effect:
```bash
docker compose down
docker rmi ssh-break-server ssh-break-client
./scripts/run-classical.sh   # will rebuild from scratch
```
`run_demo.py` does this automatically the first time it notices `tcpdump`
missing from the image, so this should only be needed if you're editing the
Dockerfile yourself.

**`ModuleNotFoundError: No module named 'kyber'`**
The pip package is `kyber-py` but the importable module is `kyber_py.ml_kem`
— `protocol.py` already handles this correctly (tries `kyber_py.ml_kem`
first, falls back to the older `kyber` layout). If you see this error, your
container image is stale — rebuild as above.

---

## 9. Contributing

- `protocol.py` — the shared wire protocol. If you touch `WeakDHKex`,
  `MLKEMKex`, or `CtrCipher`, keep `decryptor/decrypt.py`'s independent
  reimplementation of the session cipher in sync — they must produce
  byte-identical keystreams or offline decryption breaks.
- `server/server.py` / `client/client.py` — the interactive session; add new
  demo commands in the `if/elif` chain in `server.py`.
- `decryptor/decrypt.py` — the offline attack tool. Note it deliberately does
  **not** import anything from `protocol.py` — it's a from-scratch
  reimplementation, on purpose, so it demonstrably works from the pcap alone
  with no dependency on the "sender's" code.

See `README.md` for the "what's real vs. illustrative" framing — please keep
any additions honest about that distinction.
