# RUNBOOK

Step-by-step instructions for running the demo, testing it with real Wireshark,
and troubleshooting common issues. See `README.md` for the project overview.

---

## 1. Quickstart (pick your OS)

Requires Python 3.10+. First run installs dependencies and pulls Qiskit, which
takes a few minutes; every run after that is fast.

**macOS / Linux**
```bash
./run.sh
```

**Windows (PowerShell)**
```powershell
.\run.ps1
```

**Windows (Command Prompt)**
```
run.bat
```

**Any OS, directly**
```bash
python3 run.py      # macOS/Linux
python run.py        # Windows
```

All four just call `run.py`, which:
- creates a `.venv` and installs `requirements.txt` into it,
- kills anything already listening on ports 8000–8002 (so a crashed previous
  run can never leave you looking at stale data — see Troubleshooting),
- wipes `accounts_bad.json` / `accounts_good.json` for a fresh slate,
- starts the two banks and the attacker dashboard, and prints the URLs.

Open the **attacker dashboard** first: **http://127.0.0.1:8000**. Open the two
banks in other tabs from the links in its header.

Stop everything with **Ctrl-C** in the terminal running `run.py`. Give it a
second to print `stopping…` before hitting Ctrl-C again — see Troubleshooting
for why a second, impatient Ctrl-C can leave orphaned processes.

---

## 2. The demo flow

1. Attacker dashboard (:8000) — shows "listening," an empty feed, and
   `Attacker wallet: $0`.
2. Bad Insecure Bank (:8001) — **Sign up** (e.g. `alice` / `hunter2`), then
   **Sign in**.
3. Back on the dashboard: the feed lights up, Shor factors the tiny modulus,
   and a red **"Credentials intercepted"** card appears with a
   **Drain to attacker wallet** button.
4. Click it. The victim's balance on :8001 goes to `$0`; the dashboard's
   wallet balance grows by the same amount.
5. Good Secure Bank (:8002) — sign up + sign in as someone else. The dashboard
   sees the same kind of traffic but reports the key is **too large to
   factor** — credentials stay sealed, nothing to drain.

Use the feed panel's **Pause** button, **hover-to-freeze**, and filter chips
(All / Logins only / Cracked only) to slow down and find the right moment on
camera.

---

## 3. Testing with real Wireshark

The banks run over plain HTTP on loopback, so the traffic genuinely crosses
`lo0` (macOS) / `lo` (Linux) / the Windows loopback adapter. There are two
independent ways to see it — you can use either or both:

### 3a. The dashboard's built-in live capture

If Wireshark (which installs `tshark`) is detected with capture permission,
`run.py` auto-launches it in the background and the dashboard's status line
reads **"● live · tshark on lo0"** instead of **"polling capture"**. Raw TCP
lines then appear in the feed alongside the login/crack events — use the "All"
filter to see them interleaved.

**macOS permission:** Wireshark's installer offers to install **ChmodBPF**,
which grants your user account permanent capture permission — say yes to it.
If you skipped that, either re-run the Wireshark installer, or run this demo
once with `sudo python3 run.py` (not recommended long-term).

**Verify tshark can see loopback traffic on its own** before trusting the
auto-integration:
```bash
tshark -i lo0 -f "tcp port 8001" -c 3      # macOS
tshark -i lo -f "tcp port 8001" -c 3       # Linux
```
Sign in on :8001 in another tab while that's running — you should see 3
packets and the command exit. If it hangs or errors about permissions, fix
that first (see above); the dashboard will have the exact same problem.

**Windows:** live capture needs Npcap (bundled with the Wireshark installer)
and the right loopback adapter name, which varies by machine. Run `tshark -D`
to list interfaces, then set the adapter name explicitly:
```powershell
$env:SNIFF_IFACE = "Adapter for loopback traffic capture"   # or whatever tshark -D shows
.\run.ps1
```
If this doesn't work out, the built-in capture-polling fallback works exactly
the same for the demo's core logic (crack + drain) — you just won't see raw
TCP lines in the feed. Use the standalone Wireshark GUI instead (below), which
is arguably the more convincing thing to show on camera anyway.

### 3b. Standalone Wireshark GUI (recommended for video)

This is the version that looks best on screen, since it's the actual
Wireshark application, not our recreation of it.

1. Open **Wireshark.app** (or Wireshark on Windows/Linux).
2. Select the loopback interface (`lo0` on macOS, `Loopback` on Windows, `lo`
   on Linux) from the start screen.
3. In the display filter bar, type:
   ```
   tcp.port == 8001 || tcp.port == 8002
   ```
   and press Enter. (This is a *display* filter — if you want a *capture*
   filter set before starting instead, use `tcp port 8001 or tcp port 8002`.)
4. Click the shark-fin **Start** button.
5. In a browser tab, sign in on the **Bad Insecure Bank** (:8001).
6. In Wireshark, find the `POST /api/auth` packet, right-click it →
   **Follow → HTTP Stream**. You'll see the literal JSON body your browser
   sent: `wrapped_key` (the RSA-wrapped session key — a plain integer) and
   `payload_hex` (the encrypted login — meaningless-looking hex). This is a
   good beat for the video: *"here's the raw wire, in a real packet capture
   tool — and yes, that's genuinely all an eavesdropper gets."*
7. Repeat on :8002 (Good Secure Bank) for comparison — same shape of traffic,
   same tool, different key size.

---

## 4. Config knobs

| Variable | Effect |
|---|---|
| `TLS_TIER=quick` or `slow` | Bigger (but still tiny) modulus on the Bad bank, for a longer, more dramatic factorization. Default `instant`. |
| `GOOD_RSA_BITS=3072` | Stronger key on the Good bank. Default `2048`. |
| `KEEP_DATA=1` | Skip wiping `accounts_*.json` on startup (keep accounts across runs). |
| `SNIFF_IFACE=<name>` | Override the loopback interface name for live tshark capture. |
| `BAD_URL` / `GOOD_URL` | Point the dashboard at banks running elsewhere. |

Example:
```bash
TLS_TIER=slow GOOD_RSA_BITS=3072 ./run.sh
```

---

## 5. Troubleshooting

**"I'm seeing an account/login from several runs ago."**
A previous run was probably interrupted uncleanly (e.g. a rushed double
Ctrl-C), leaving a bank process alive in the background with its old
in-memory capture log, still bound to its port. `run.py` now force-kills
anything on ports 8000–8002 at the start of every run specifically to prevent
this — make sure you're on the current version (`run.py` should exist; if
you're still running an old `run.sh` without the "Making sure ports … are
free" step, update).

**Sign-in / sign-up hangs on "encrypting & sending…" forever.**
`bank.js` now times out after 8 seconds and shows a red error if the backend
doesn't respond, so this shouldn't happen anymore. If you do see it hang, the
backend process for that bank likely isn't running — check the terminal
running `run.py` for errors, and confirm you can load `http://127.0.0.1:8001/`
and `:8002/` directly.

**A previous run's servers won't die / port already in use.**
```bash
# macOS/Linux
lsof -ti tcp:8000,8001,8002 | xargs kill -9

# Windows (PowerShell)
Get-NetTCPConnection -LocalPort 8000,8001,8002 -State Listen |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```
Then re-run. `run.py` also does this automatically at startup, so this is
only needed if something's oddly stuck.

**`pip install` is slow / seems stuck on the first run.**
Qiskit + Qiskit Aer are large packages; the first install can take several
minutes depending on your connection. Subsequent runs reuse the same `.venv`
and are fast.

**Live tshark capture never turns on ("polling capture" never changes).**
See section 3a above — usually a capture-permission issue (macOS: install
ChmodBPF) or the interface name not matching (Windows: use `tshark -D` to find
the right name and set `SNIFF_IFACE`). The demo's core functionality (crack,
decrypt, drain) works identically either way; only the raw-packet lines in the
feed depend on this.

**Messy `KeyboardInterrupt` / `uvloop` traceback on Ctrl-C.**
Cosmetic — a known noisy interaction between newer uvicorn/uvloop and recent
Python versions on shutdown. It doesn't indicate a real problem. Give the
script a couple of seconds after the first Ctrl-C before pressing it again;
pressing it twice quickly is what can orphan processes (see the first item
above).

---

## 6. Contributing

Issues and PRs welcome. A few useful entry points if you want to extend this:

- `backend/channel.py` / `frontend/channel.js` — the wire protocol (RSA key
  wrap + stream cipher). Keep these two in lock-step; there's a byte-for-byte
  compatibility test described in the PR history if you touch either.
- `backend/shor.py` — the actual Shor's-algorithm implementation (Qiskit +
  Aer simulator).
- `backend/bank_server.py` — shared factory for both banks; theme/key
  strength are the only real differences between them.
- `backend/app.py` — the attacker dashboard: live feed (SSE), auto-crack, and
  the drain/wallet endpoints.

See `README.md` for the "what's real vs. scaled down" framing — please keep
any additions honest about that distinction.
