"""Deliberately vulnerable demo target for the Vaultrix proof layer.

A stand-in for an AI-built Supabase+Next app: it checks that you are logged in,
but NOT that the record is yours — the textbook IDOR. Set VAULTRIX_FIXED=1 to
run the patched version, which enforces ownership. stdlib only, so the sandbox
can build it from one tiny image.

All data is fake and seeded from SEED (two users, each owning one record).
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Seeded at build time by the sandbox generator; defaults let the file run alone.
SEED = json.loads(os.environ.get("VAULTRIX_SEED") or json.dumps({
    "users": [
        {"email": "alice@demo.test", "password": "pw-a", "token": "tok-alice",
         "record_id": "1", "marker": "ALICE_SECRET_7f3a"},
        {"email": "bob@demo.test", "password": "pw-b", "token": "tok-bob",
         "record_id": "2", "marker": "BOB_SECRET_9a1c"},
    ]
}))
FIXED = os.environ.get("VAULTRIX_FIXED") == "1"

BY_TOKEN = {u["token"]: u for u in SEED["users"]}
BY_EMAIL = {u["email"]: u for u in SEED["users"]}
BY_RECORD = {u["record_id"]: u for u in SEED["users"]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        return BY_TOKEN.get(token)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/health":
            return self._send(200, {"ok": True})
        if p.path.startswith("/api/records/"):
            caller = self._user()
            if caller is None:                       # authentication IS checked
                return self._send(401, {"error": "login required"})
            rid = p.path.rsplit("/", 1)[-1]
            owner = BY_RECORD.get(rid)
            if owner is None:
                return self._send(404, {"error": "no such record"})
            if FIXED and owner["token"] != caller["token"]:   # authorization — only in the fix
                return self._send(403, {"error": "not your record"})
            # THE BUG (unfixed): any logged-in user gets any record.
            return self._send(200, {"id": rid, "owner": owner["email"], "secret": owner["marker"]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            try:
                creds = json.loads(self.rfile.read(length) or "{}")
            except json.JSONDecodeError:
                creds = {}
            u = BY_EMAIL.get(creds.get("email"))
            if u and u["password"] == creds.get("password"):
                return self._send(200, {"access_token": u["token"]})
            return self._send(401, {"error": "bad credentials"})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
