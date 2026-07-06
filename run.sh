#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "== Q-DAY setup =="
if [ ! -d .venv ]; then
  echo "Creating virtual environment (.venv)…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing dependencies (first run downloads Qiskit — can take a few minutes)…"
pip install --upgrade pip
pip install -r requirements.txt

# Load .env if present (IBM credentials). Safe when the file is missing.
if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

# If an IBM token is set but the runtime isn't installed, install it now
# so the "IBM Quantum (hardware)" option becomes available.
if [ -n "${IBM_QUANTUM_TOKEN}" ]; then
  python -c "import qiskit_ibm_runtime" 2>/dev/null || {
    echo "IBM token detected — installing qiskit-ibm-runtime…"
    pip install qiskit-ibm-runtime
  }
fi

# Figure out the LAN IP so a friend on the same Wi-Fi can connect.
LAN_IP=""
if command -v ipconfig >/dev/null 2>&1; then          # macOS
  LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
fi
if [ -z "$LAN_IP" ]; then                              # Linux fallback
  LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

echo ""
echo "=================================================================="
echo "  Q-DAY is running.  Press Ctrl-C to stop."
echo "    On this machine:   http://127.0.0.1:8000"
if [ -n "$LAN_IP" ]; then
  echo "    Same Wi-Fi/LAN:    http://$LAN_IP:8000   <- share this with a friend"
else
  echo "    (Could not detect your LAN IP automatically.)"
fi
echo "=================================================================="
echo ""

cd backend
# Bind to 0.0.0.0 so other devices on the network can reach it.
uvicorn main:app --host 0.0.0.0 --port 8000 --reload