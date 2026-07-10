#!/usr/bin/env bash
# Thin wrapper — all the real logic lives in run_demo.py.
cd "$(dirname "$0")/.."
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
exec "$PY" run_demo.py pqc
