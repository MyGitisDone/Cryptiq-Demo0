#!/usr/bin/env bash
# Thin wrapper — all the real logic lives in run.py so macOS/Linux/Windows
# stay in sync from one file.
set -e
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
exec "$PY" run.py
