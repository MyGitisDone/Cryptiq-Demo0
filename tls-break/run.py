#!/usr/bin/env python3
"""
run.py — cross-platform launcher for the Q-DAY bank interception demo.

Works the same way on macOS, Linux, and Windows:

    python3 run.py        (macOS / Linux)
    python run.py         (Windows)

or via the thin per-OS wrappers: ./run.sh, run.bat, run.ps1 — they all just
call this file. Everything OS-specific (virtualenv paths, killing stale
processes on our ports, finding the LAN IP, picking a loopback interface name)
is handled here so there's exactly one place to maintain.
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
VENV_DIR = ROOT / ".venv"
IS_WINDOWS = platform.system() == "Windows"
PORTS = (8000, 8001, 8002)


def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def ensure_venv() -> None:
    if not VENV_DIR.exists():
        print("Creating virtual environment…")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    print("Installing dependencies (first run pulls Qiskit — a few minutes)…")
    py = str(venv_python())
    subprocess.run([py, "-m", "pip", "install", "--upgrade", "pip"],
                    check=True, stdout=subprocess.DEVNULL)
    subprocess.run([py, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)


def lan_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # no packet actually sent; just picks the outbound interface
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def free_port(port: int) -> None:
    """Kill whatever's already listening on `port`, so every run starts clean.
    Needs psutil; silently skipped if it's not installed."""
    try:
        import psutil
    except ImportError:
        return
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception:
        return
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port and c.pid:
            try:
                proc = psutil.Process(c.pid)
                print(f"  killing stale process on port {port} (pid {c.pid}, {proc.name()})")
                proc.kill()
            except Exception:
                pass


def sniff_iface() -> str:
    env = os.environ.get("SNIFF_IFACE")
    if env:
        return env
    system = platform.system()
    if system == "Darwin":
        return "lo0"
    if system == "Linux":
        return "lo"
    # Windows loopback capture needs Npcap; the exact adapter name varies by
    # machine. Run `tshark -D` to list interfaces and set SNIFF_IFACE yourself
    # if this default doesn't match. Live capture is optional — everything
    # else works via the built-in capture-polling fallback either way.
    return "Adapter for loopback traffic capture"


def main() -> None:
    print("== Q-DAY bank interception demo ==")
    ensure_venv()

    print("Making sure ports 8000-8002 are free…")
    for port in PORTS:
        free_port(port)
    time.sleep(1)

    if os.environ.get("KEEP_DATA") != "1":
        for name in ("accounts_bad.json", "accounts_good.json"):
            fp = BACKEND / name
            if fp.exists():
                fp.unlink()
        print("Cleared saved accounts (fresh slate). Set KEEP_DATA=1 to preserve them across runs.")

    iface = sniff_iface()
    env = dict(os.environ, SNIFF_IFACE=iface)
    py = str(venv_python())

    print("Starting the two banks…")
    bg_procs = [
        subprocess.Popen([py, "-m", "uvicorn", "server_bad:app", "--host", "0.0.0.0", "--port", "8001",
                          "--log-level", "warning", "--no-access-log"], cwd=str(BACKEND), env=env),
        subprocess.Popen([py, "-m", "uvicorn", "server_good:app", "--host", "0.0.0.0", "--port", "8002",
                          "--log-level", "warning", "--no-access-log"], cwd=str(BACKEND), env=env),
    ]
    time.sleep(3)

    ip = lan_ip()
    print()
    print("=" * 70)
    print("  ATTACKER DASHBOARD (open this):   http://127.0.0.1:8000")
    if ip:
        print(f"     on your LAN:                    http://{ip}:8000")
    print()
    print("  Victim banks (open in other tabs, sign up + sign in):")
    print("     Bad Insecure Bank:   http://127.0.0.1:8001   (gets hacked)")
    print("     Good Secure Bank:    http://127.0.0.1:8002   (resists)")
    print()
    print(f"  Live Wireshark capture: SNIFF_IFACE={iface}")
    print("  (needs tshark + capture permission; falls back to polling if absent)")
    print("  Ctrl-C to stop everything.")
    print("=" * 70)
    print()

    dash = None
    try:
        dash = subprocess.Popen([py, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"],
                                 cwd=str(BACKEND), env=env)
        dash.wait()
    except KeyboardInterrupt:
        pass
    finally:
        print("\nstopping…")
        all_procs = bg_procs + ([dash] if dash else [])
        for p in all_procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        for p in all_procs:
            try:
                p.kill()
            except Exception:
                pass


if __name__ == "__main__":
    main()
