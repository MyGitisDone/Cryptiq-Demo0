# Q-DAY — Bank Interception Demo

**"Harvest now, decrypt later," made visible in one browser tab.**

Two real bank websites you can sign up for, and an attacker dashboard that
taps the wire between them. Sign into the **Bad Insecure Bank** and watch a
real implementation of Shor's algorithm factor its key, decrypt your login,
and drain your account — live, in seconds. Sign into the **Good Secure Bank**
and watch the exact same attack fail.

Built for post-quantum migration pitches, security awareness demos, and
conference talks. Runs entirely on your own machine; nothing leaves it.

---

## Quickstart

Requires Python 3.10+.

| OS | Command |
|---|---|
| macOS / Linux | `./run.sh` |
| Windows (PowerShell) | `.\run.ps1` |
| Windows (cmd) | `run.bat` |
| Any OS | `python3 run.py` (or `python run.py` on Windows) |

First run installs dependencies (a few minutes, mostly Qiskit); every run
after that is fast and starts with a clean slate. Then open the **attacker
dashboard**:

**http://127.0.0.1:8000**

...and the two banks, linked from its header, in other tabs.

Full walkthrough, real-Wireshark instructions, config options, and
troubleshooting: see **[RUNBOOK.md](RUNBOOK.md)**.

---

## What you'll see

1. Sign up and sign in on the **Bad Insecure Bank** (tiny RSA key).
2. The dashboard's live feed factors the key, decrypts your login, and pops a
   loot card with your stolen credentials.
3. One click — **Drain to attacker wallet** — zeroes your balance there and
   grows the attacker's wallet by the same amount.
4. Do the same on the **Good Secure Bank** (a full-size key, standing in for
   a post-quantum key exchange like ML-KEM). Same attack. It just fails.

Every login is genuinely encrypted with a genuine RSA key exchange; the
browser and server crypto were verified byte-for-byte. What's scaled down is
the *size* of the Bad bank's key, so a laptop can factor it in seconds — real
RSA-2048 is identical math at a size no computer can reach yet, which is the
whole point.

---

## What's real, what's illustrative

Being upfront about this so nobody mistakes it for more than it is:

- **Real:** the Shor's-algorithm implementation (Qiskit + a local simulator)
  genuinely factors the modulus; your credentials are genuinely encrypted
  client-side before they touch the network; capture → recover key → decrypt
  is exactly the mechanics of a real harvest-now-decrypt-later attack.
- **Scaled down:** the Bad bank's RSA modulus is tiny (e.g. `N = 15`) so the
  simulator can factor it interactively. This is the entire reason to migrate
  *before* quantum hardware catches up to real key sizes — not because the
  attack is fake, but because it currently only works at toy scale.
- **Simplified:** the record cipher that protects a login once a key is
  agreed is a transparent SHA-256 stream cipher, not AES-GCM, so there are
  zero heavy cryptographic dependencies. The security a quantum computer
  threatens lives in the **key exchange**, which is modeled faithfully.

See [RUNBOOK.md](RUNBOOK.md) for architecture notes if you want to extend or
audit this.

---

## Project layout

```
backend/
  app.py            attacker dashboard — live feed, auto-crack, drain, wallet
  bank_server.py     shared factory both banks are built from
  server_bad.py      Bad Insecure Bank (tiny RSA)
  server_good.py     Good Secure Bank (full-size key)
  bank.py            accounts: signup / signin / balance / transfer
  channel.py         wire protocol: RSA key wrap + stream cipher
  shor.py            Shor's algorithm (Qiskit + Aer simulator)
  sniffer.py         optional live tshark integration
frontend/
  dashboard.*        attacker console
  bank.*             the bank site both banks serve
  channel.js         browser-side half of the wire protocol
run.py               cross-platform launcher (macOS/Linux/Windows)
run.sh / run.bat / run.ps1   thin per-OS wrappers around run.py
RUNBOOK.md           full walkthrough, Wireshark testing, troubleshooting
```

---

## Disclaimer

Educational only. Toy keys, a demo record cipher, and a bank that exists to
be broken. Don't protect anything real with any of this.

## License

MIT — see [LICENSE](LICENSE).
