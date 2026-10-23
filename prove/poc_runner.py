"""Turn a live sandbox + its seed into authenticated clients, then run the provers.

Auth differs per stack, so login is one small function passed in. The default
fits the demo target and any app with a JSON `POST /login -> {access_token}`;
`supabase_login` fits the real stack's GoTrue endpoint.
"""
from __future__ import annotations

from core.findings import Finding
from core.net import Client
from core.seed import Seed, SeedUser
from prove import idor_prober


def json_login(base_url: str, user: SeedUser) -> Client:
    c = Client(base_url)
    r = c.post("/login", json={"email": user.email, "password": user.password})
    token = _token(r)
    if not token:
        raise LoginFailed(f"could not log in {user.email}: {r.status} {r.error or r.body[:120]}")
    return c.bearer(token)


def supabase_login(base_url: str, user: SeedUser, anon_key: str) -> Client:
    c = Client(base_url, headers={"apikey": anon_key})
    r = c.post("/auth/v1/token?grant_type=password",
               json={"email": user.email, "password": user.password})
    token = _token(r)
    if not token:
        raise LoginFailed(f"GoTrue rejected {user.email}: {r.status}")
    return c.bearer(token)


def _token(resp) -> str | None:
    import json
    try:
        return (json.loads(resp.body) or {}).get("access_token")
    except Exception:
        return None


class LoginFailed(Exception):
    pass


def run(base_url: str, seed: Seed, login=json_login, log=lambda _m: None) -> list[Finding]:
    clients: dict[str, Client] = {}
    for u in seed.users:
        try:
            clients[u.email] = login(base_url, u)
            log(f"logged in {u.email}")
        except LoginFailed as e:
            log(str(e))  # a user we cannot authenticate simply is not used as an attacker
    findings = idor_prober.probe(seed, clients)
    log(f"idor_prober: {len(findings)} proven finding(s)")
    return findings


if __name__ == "__main__":  # self-check end-to-end over real HTTP, no docker
    import os
    import threading
    from http.server import ThreadingHTTPServer
    import importlib.util

    demo = os.path.join(os.path.dirname(__file__), "..", "examples", "sandbox-idor-demo", "app.py")
    spec = importlib.util.spec_from_file_location("demo_app", demo)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        from sandbox.generator import _demo_seed
        fs = run(base, _demo_seed())
        assert len(fs) == 2, f"both directions should prove: {len(fs)}"
        assert all(f.proof.value == "proven" for f in fs)
        assert any("BOB_SECRET_9a1c" in f.evidence for f in fs)
    finally:
        srv.shutdown()
    print("poc_runner self-check ok")
