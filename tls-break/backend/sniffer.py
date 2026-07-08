"""
sniffer.py — optional live capture using tshark (installed with Wireshark).

If tshark is present and has capture permission, we spawn it on the loopback
interface and stream real packet metadata to the dashboard's live feed. If it
isn't available, the dashboard falls back to polling each bank's /capture
endpoint, so the demo always works.

The crackable material (the RSA modulus, the wrapped key, the ciphertext) is read
from the banks' harvested capture — i.e. exactly the bytes that were on the wire.
tshark provides the authentic "packets are really flowing" visual on top.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import threading
from typing import Callable


def tshark_path() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    system = platform.system()
    candidates = []
    if system == "Darwin":
        candidates.append("/Applications/Wireshark.app/Contents/MacOS/tshark")
    elif system == "Windows":
        candidates += [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def available() -> bool:
    return tshark_path() is not None


def _find(d, suffix: str):
    """Recursively find the first value whose key ends with `suffix`."""
    if isinstance(d, dict):
        for k, v in d.items():
            if k.endswith(suffix) and not isinstance(v, (dict, list)):
                return v
            found = _find(v, suffix)
            if found is not None:
                return found
    elif isinstance(d, list):
        for item in d:
            found = _find(item, suffix)
            if found is not None:
                return found
    return None


class LiveSniffer:
    def __init__(self, iface: str, ports: tuple[int, ...]):
        self.iface = iface
        self.ports = ports
        self.proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, on_packet: Callable[[dict], None]) -> bool:
        tshark = tshark_path()
        if not tshark:
            return False
        bpf = " or ".join(f"tcp port {p}" for p in self.ports)
        cmd = [tshark, "-i", self.iface, "-f", bpf, "-l", "-T", "ek"]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except Exception:
            return False

        def reader():
            seq = 0
            for line in self.proc.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line or '"layers"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                layers = obj.get("layers", obj)
                sp = _find(layers, "srcport"); dp = _find(layers, "dstport")
                ln = _find(layers, "frame_len") or _find(layers, "len")
                if sp is None or dp is None:
                    continue
                seq += 1
                proto = "HTTP" if _find(layers, "http_http") is not None else "TCP"
                on_packet({
                    "seq": seq, "src_port": int(sp), "dst_port": int(dp),
                    "length": int(ln) if ln else 0, "proto": proto,
                })
            return

        self._thread = threading.Thread(target=reader, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self.proc:
            self.proc.terminate()
