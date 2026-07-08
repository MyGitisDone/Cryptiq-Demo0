"""
bank.py — minimal but real bank: sign up, sign in, view account, transfer out.

Accounts persist to a JSON file so that a victim's browser and an attacker's
browser (and the attacker dashboard) all see the same balances. Two separate
files back the two banks so they're independent institutions.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path


class Bank:
    def __init__(self, store_path: str, name: str, opening_balance: int = 84120):
        self.path = Path(store_path)
        self.name = name
        self.opening_balance = opening_balance
        self._lock = threading.Lock()
        self._sessions: dict[str, str] = {}   # token -> username
        if not self.path.exists():
            self._write({})

    # ---- persistence ----
    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def _write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2))

    # ---- password hashing ----
    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.sha256((salt + password).encode()).hexdigest()

    # ---- operations ----
    def signup(self, username: str, password: str) -> dict:
        username = username.strip()
        with self._lock:
            data = self._read()
            if username in data:
                return {"ok": False, "error": "That username already exists."}
            salt = secrets.token_hex(4)
            data[username] = {
                "salt": salt, "pw": self._hash(password, salt),
                "balance": self.opening_balance,
                "account_no": "ACME-" + "".join(secrets.choice("0123456789") for _ in range(10)),
                "routing": "".join(secrets.choice("0123456789") for _ in range(9)),
                "opened": time.strftime("%Y-%m-%d"),
            }
            self._write(data)
        return {"ok": True}

    def signin(self, username: str, password: str) -> dict:
        username = username.strip()
        with self._lock:
            data = self._read()
            acct = data.get(username)
            if not acct or acct["pw"] != self._hash(password, acct["salt"]):
                return {"ok": False, "error": "Invalid username or password."}
            token = secrets.token_hex(16)
            self._sessions[token] = username
        return {"ok": True, "token": token}

    def _user_for(self, token: str) -> str | None:
        return self._sessions.get(token)

    def account(self, token: str) -> dict:
        user = self._user_for(token)
        if not user:
            return {"ok": False, "error": "Not signed in."}
        data = self._read()
        a = data[user]
        return {"ok": True, "username": user, "balance": a["balance"],
                "account_no": a["account_no"], "routing": a["routing"], "opened": a["opened"]}

    def transfer_out(self, token: str, to: str = "attacker", amount: int | None = None) -> dict:
        user = self._user_for(token)
        if not user:
            return {"ok": False, "error": "Not signed in."}
        with self._lock:
            data = self._read()
            bal = data[user]["balance"]
            moved = bal if amount is None else min(amount, bal)
            data[user]["balance"] = bal - moved
            self._write(data)
        return {"ok": True, "moved": moved, "to": to, "balance": data[user]["balance"]}
