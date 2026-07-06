# Q-DAY — watch a quantum computer break encryption

An open-source, run-it-yourself proof of concept for the post-quantum migration
problem. It stores one secret two ways — behind **RSA** and behind **ML-KEM
(FIPS 203)** — then points a real implementation of **Shor's algorithm** at both.
RSA falls. ML-KEM holds. You watch it happen live in the browser.

> Built as a public demo for **CryptiQ**, which helps organizations
> inventory their cryptography, produce a board-ready migration plan, and ship
> the tooling to move to quantum-safe algorithms.

---

## Read this first — what is and isn't real

Being precise here is what makes the demo credible to a security team or a
technical investor. Overclaiming is what gets it dismissed.

**Real:**
- The quantum circuit is a genuine implementation of Shor's period-finding
  (quantum phase estimation over modular exponentiation) plus the classical
  continued-fractions post-processing. No hard-coded answers.
- It really factors the RSA modulus, really reconstructs the private key, and
  really decrypts the captured ciphertext.
- ML-KEM is a real FIPS-203 key exchange (via `kyber-py`).
- The hybrid scheme (RSA wraps a session key; a symmetric cipher protects the
  data) is exactly how TLS works, and is why **"harvest now, decrypt later"** is
  a threat today.

**Deliberately small:**
- The RSA modulus is a product of two *small* primes (N ≤ 63) so the circuit
  fits on a laptop simulator or a small quantum device.
- **This does not break real RSA-2048.** No machine on Earth can today. Breaking
  RSA-2048 needs on the order of thousands of logical (millions of noisy)
  qubits; current devices have ~hundreds of noisy qubits. The *method* you watch
  is identical — only the size differs, and that gap is the entire point of
  starting migration now.

**A note on hashing:** password *hashes* (SHA-2, bcrypt) are **not** what Shor
breaks and **not** what ML-KEM replaces. The quantum threat is against
*public-key* crypto — key exchange and signatures (RSA, ECC, Diffie–Hellman).
This demo targets that correctly. (Hashes face only Grover's quadratic speedup,
handled by using longer digests.) If your marketing says "quantum computers will
crack your passwords," a cryptographer will bounce it — so we don't.

---

## What you'll see

**Solo mode** — enter a secret (say, a password), pick a key-difficulty tier, and
hit **Seal & attack**:

1. The secret is sealed into two vaults — RSA and ML-KEM — shown side by side
   with the *same* comparison rows (type, algorithm, hardness, key size, quantum
   attack, status) so it reads as a true comparison.
2. Shor's algorithm runs; a phase-estimation dial spins while the RSA vault's
   ciphertext glyphs scramble.
3. The modulus factors, the private key is reconstructed, the session key is
   unwrapped, and the ciphertext **collapses into the original plaintext**.
4. The same attack is pointed at ML-KEM — and there's nothing for it to grab.

**Two-player mode** (best for demos) — one person is the **Defender**, the other
the **Attacker**, in two browser tabs on the same machine:

- The Defender creates a room, gets a 4-letter code, and seals a secret.
- The Attacker joins with the code. They **never see the secret** — only the
  public key and ciphertext, exactly like a real eavesdropper.
- The Attacker runs the break; the recovered secret appears live on *both*
  screens. This is what makes the reveal land: the attacker genuinely didn't
  know it.

### About the hash on screen

Each vault shows the secret's **SHA-256 hash** labeled *"stored at rest —
survives quantum."* That's deliberate and correct: hashing is **not** what the
quantum attack breaks. Shor targets the **RSA key protecting data in transit**
(labeled as such). Grover's algorithm only halves a hash's security, so SHA-256
stays strong post-quantum. Showing both, correctly labeled, is the real lesson:
*your hashing is fine; your key exchange is the problem.*

A live terminal streams every step (base choice, measured order, factors,
recovered key) via Server-Sent Events.

---

## Quick start

Requires **Python 3.10+**.

```bash
git clone <your-repo-url> q-day
cd q-day
./run.sh
```

Then open **http://127.0.0.1:8000**.

`run.sh` binds to your whole network and prints a second URL like
`http://192.168.x.x:8000`. Anyone on the **same Wi-Fi/LAN** can open that URL —
that's how a friend joins your two-player room from their own laptop. (If they
can't reach it, your machine's firewall is likely blocking incoming connections
on port 8000.)

`run.sh` creates a virtualenv, installs dependencies, and starts the server. To
do it manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd backend
uvicorn main:app --reload --port 8000
```

### Difficulty tiers (simulator timing on a typical laptop)

| Tier    | Modulus | Total qubits | Time      |
|---------|---------|--------------|-----------|
| instant | N = 15  | ~12          | ~1 s      |
| quick   | N = 21  | ~15          | ~10–15 s  |
| slow    | N ≤ 63  | ~18          | ~30–70 s  |

The ceiling (`MAX_N = 63` in `backend/main.py`) exists because a statevector
simulator grows exponentially with qubit count. Raise it only if you know your
machine can take it.

---

## Running on real IBM Quantum hardware (optional)

Yes, it's free. IBM's **Open Plan** gives ~10 minutes of real QPU time per
28-day rolling window, no credit card. The backend abstracts where circuits run,
so you can point it at real hardware.

1. Create a free account at <https://quantum.cloud.ibm.com>.
2. On the dashboard, create an **API key** (44 characters) and copy it. Optionally
   copy your **instance CRN** from the Instances page.
3. Install the runtime and set credentials:
   ```bash
   pip install qiskit-ibm-runtime
   cp .env.example .env      # paste your API key (and optional CRN) into .env
   ```
4. Restart the server. The **Backend** dropdown will enable *IBM Quantum
   (hardware)*.

**Important — hardware is smaller than the simulator, not bigger.** This
surprises people, and it's a key part of the story:

| | Aer simulator | Real IBM hardware (today) |
|---|---|---|
| Biggest reliable factor | N ≈ 63 | N = 15 (maybe 21) |
| Speed | seconds | minutes + queue |
| Correctness | always exact | often wrong (noise) |

Real quantum computers have more qubits (100+), but their error rates destroy
the delicate interference Shor's algorithm relies on, so anything past N=15
returns noise. The famous public Shor-on-hardware results max out at factoring 15
and 21. That's not a weakness in the demo — it's the pitch: **the algorithm is
ready; the hardware is catching up; migrate before it arrives.**

---

## Architecture

```
frontend/                 zero-build vanilla JS + CSS (IBM Plex type system)
  index.html              hero, two-vault lab, live terminal
  styles.css              animations: glyph collapse, phase ring, lattice
  app.js                  config, setup, consumes the SSE attack stream

backend/                  FastAPI
  main.py                 API + Server-Sent Events streaming
  shor.py                 Shor's period-finding (QPE) + factor recovery
  rsa_toy.py              tiny textbook RSA + hybrid (session-key) encryption
  mlkem_demo.py           ML-KEM exchange via kyber-py + why Shor can't touch it
  quantum_backend.py      Aer (local) or IBM Runtime (hardware) sampler
  models.py               request schemas
```

The one abstraction worth knowing: `quantum_backend.get_sampler()` returns a
`sampler(circuit, shots)` callable. `shor.run_shor` takes that callable, so the
identical algorithm runs on the simulator or on IBM hardware with no change.

---

## Endpoints

| Method | Path                     | Purpose                                     |
|--------|--------------------------|---------------------------------------------|
| GET    | `/api/config`            | tiers + which backends are available        |
| POST   | `/api/setup`             | solo: seal a secret under RSA + ML-KEM      |
| POST   | `/api/room`              | two-player: create a room → `{code}`        |
| POST   | `/api/room/{code}/seal`  | defender seals a secret into the room       |
| GET    | `/api/room/{code}`       | attacker fetches the public (breakable) target |
| GET    | `/api/room/{code}/result`| defender polls for the reveal               |
| POST   | `/api/attack`            | SSE stream of Shor breaking RSA (solo or room) |
| GET    | `/api/mlkem-attack`      | reports (correctly) that there's no attack  |

---

## Extending it

- **Two-player mode:** already built (see above). To go beyond localhost, swap
  the in-memory room store in `main.py` for Redis and add WebSockets.
- **Signatures:** add an ML-DSA (Dilithium) panel alongside the KEM.
- **Grover panel:** contrast the *quadratic* speedup against symmetric crypto to
  explain why AES-256 is fine but RSA isn't.
- **Noise models:** run Aer with a fake-backend noise model to show why error
  correction matters before hardware factors anything real.

---

## Disclaimer

Educational only. The RSA keys are toy-sized and the crypto libraries here are
not hardened for production. Do not protect anything real with this code — the
whole point is that it can be broken.

## License

MIT — see [LICENSE](LICENSE).