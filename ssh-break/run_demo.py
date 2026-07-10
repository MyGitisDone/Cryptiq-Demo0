#!/usr/bin/env python3
"""
run_demo.py — cross-platform launcher for the HNDL SSH demo.

Works identically on macOS, Linux, and Windows because everything OS-specific
is just a `docker` / `docker compose` subprocess call — Docker itself hides
the container internals, so the host OS barely matters here. The only truly
interactive piece (the SSH session) inherits your terminal directly.

Usage:
    python3 run_demo.py classical
    python3 run_demo.py pqc

or via the thin per-OS wrappers in scripts/ — they all just call this file.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CAPTURES = ROOT / "captures"

BANNERS = {
    "classical": ("DEMO 1 — Classical (Weak DH)", "weak", "ssh-classical.pcap"),
    "pqc":       ("DEMO 2 — ML-KEM (Quantum-Safe)", "mlkem", "ssh-pqc.pcap"),
}

COMMAND_HINTS = """  Try:  whoami
        ls
        cat payroll.csv
        hostname
        exit"""


def box(lines: list[str]) -> None:
    width = max(len(l) for l in lines) + 2
    print("╔" + "═" * width + "╗")
    for l in lines:
        print("║ " + l.ljust(width - 1) + "║")
    print("╚" + "═" * width + "╝")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, **kw)


def docker_compose_cmd() -> list[str]:
    """Prefer 'docker compose' (v2, built into modern Docker); fall back to
    the standalone 'docker-compose' (v1) if that's what's installed."""
    if run(["docker", "compose", "version"], capture_output=True).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    print("✗  Neither 'docker compose' nor 'docker-compose' found. Install Docker Desktop.")
    sys.exit(1)


def tcpdump_present(container: str) -> bool:
    return run(["docker", "exec", container, "which", "tcpdump"],
               capture_output=True).returncode == 0


def tcpdump_running(container: str) -> bool:
    out = run(["docker", "top", container], capture_output=True, text=True)
    return "tcpdump" in out.stdout


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in BANNERS:
        print("Usage: python3 run_demo.py [classical|pqc]")
        sys.exit(1)

    mode = sys.argv[1]
    title, kex_mode, pcap_name = BANNERS[mode]
    CAPTURES.mkdir(exist_ok=True)

    print()
    box([title])
    print()

    dc = docker_compose_cmd()
    env_flag = [f"KEX_MODE={kex_mode}"]

    print("Starting containers...")
    import os
    env = dict(os.environ, KEX_MODE=kex_mode)
    r = run(dc + ["up", "-d", "--build"], cwd=ROOT, env=env)
    if r.returncode != 0:
        print("✗  docker compose up failed.")
        sys.exit(1)
    time.sleep(3)

    print("Checking tcpdump is available inside ssh-server...")
    if not tcpdump_present("ssh-server"):
        print("  Rebuilding without cache to pick up Dockerfile changes...")
        run(dc + ["down"], cwd=ROOT, env=env)
        run(dc + ["build", "--no-cache"], cwd=ROOT, env=env)
        run(dc + ["up", "-d"], cwd=ROOT, env=env)
        time.sleep(3)
    print("  ✔ tcpdump found")

    print(f"Starting capture inside ssh-server → captures/{pcap_name}")
    run(["docker", "exec", "-d", "ssh-server", "sh", "-c",
        "tcpdump -i eth0 -w /tmp/capture.pcap tcp >/tmp/tcpdump.log 2>&1"])
    time.sleep(1.5)

    if not tcpdump_running("ssh-server"):
        print("  ✗ tcpdump not running. Log from container:")
        log = run(["docker", "exec", "ssh-server", "cat", "/tmp/tcpdump.log"],
                  capture_output=True, text=True)
        print(log.stdout)
        run(dc + ["down"], cwd=ROOT, env=env)
        sys.exit(1)
    print("  ✔ tcpdump running inside container")

    print()
    box(["SSH session ready — type your commands", "", *COMMAND_HINTS.strip("\n").split("\n")])
    print()

    # Interactive session — inherits this terminal directly on all platforms.
    run(["docker", "exec", "-it", "ssh-client", "python3", "/app/client/client.py", "demo@server"])

    print()
    print("Stopping capture and copying pcap to host...")
    run(["docker", "exec", "ssh-server", "pkill", "tcpdump"], capture_output=True)
    time.sleep(1.5)
    dest = CAPTURES / pcap_name
    run(["docker", "cp", f"ssh-server:/tmp/capture.pcap", str(dest)], capture_output=True)

    if dest.exists() and dest.stat().st_size > 0:
        size = dest.stat().st_size
        print()
        print(f"  ✔ captures/{pcap_name}  ({size} bytes)")
        print()
        print(f"  Open in Wireshark:  wireshark captures/{pcap_name}")
        print(f"  Decrypt offline:    python3 decryptor/decrypt.py captures/{pcap_name}")
    else:
        print("  ✗  pcap missing or empty.")
        log = run(["docker", "exec", "ssh-server", "cat", "/tmp/tcpdump.log"],
                  capture_output=True, text=True)
        print(log.stdout)
    print()

    run(dc + ["down"], cwd=ROOT, env=env, capture_output=True)


if __name__ == "__main__":
    main()
