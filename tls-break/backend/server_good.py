"""Good Secure Bank (port 8002) — full-size key exchange, quantum-safe stand-in.
Run:  uvicorn server_good:app --port 8002"""
from bank_server import make_bank_app
import os

app = make_bank_app(
    theme="good",
    name="Good Secure Bank",
    tagline="We care about your safety. Quantum-safe key exchange, always.",
    store=os.environ.get("GOOD_STORE", "accounts_good.json"),
    tiny=False,
    rsa_bits=int(os.environ.get("GOOD_RSA_BITS", "2048")),
)
