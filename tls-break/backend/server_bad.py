"""Bad Insecure Bank (port 8001) — tiny RSA, breakable by Shor.
Run:  uvicorn server_bad:app --port 8001"""
from bank_server import make_bank_app
import os

app = make_bank_app(
    theme="bad",
    name="Bad Insecure Bank",
    tagline="We don't care if attackers hack us. Encryption is expensive!",
    store=os.environ.get("BAD_STORE", "accounts_bad.json"),
    tiny=True,
    tier=os.environ.get("TLS_TIER", "instant"),
)
